import base64
import csv
import json
import os
import random
import string
import time
import re
import struct
import threading
import concurrent.futures
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin

from curl_cffi import requests
from bs4 import BeautifulSoup

from g import (
    EmailService,
    TurnstileService,
    UserAgreementService,
    NsfwSettingsService,
    CastleService,
    same_session_register,
    parse_proxy_spec,
)

try:
    from g import AntibotService
except Exception:  # pragma: no cover
    AntibotService = None  # type: ignore


# 基础配置
site_url = "https://accounts.x.ai"
_BASE_DIR = Path(__file__).resolve().parent
_ACTION_CACHE_FILE = _BASE_DIR / "logs" / "action_id_cache.json"
# chrome120 在部分 Windows/curl_cffi 组合下连 accounts.x.ai 会 curl(28) 超时，改用更稳指纹
DEFAULT_IMPERSONATE = "chrome131"
# device flow / 导入专用指纹池（TLS 失败时轮换）
DEVICE_FLOW_IMPERSONATES = ("chrome131", "chrome136", "chrome124", "chrome")
# 与 grokcli-2api sso_to_auth_json 保持一致：只有 device flow 换到 token 才算可导入
OIDC_ISSUER = "https://auth.x.ai"
GROK_CLI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)
CHROME_PROFILES = [
    {"impersonate": "chrome124", "version": "124.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome131", "version": "131.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome136", "version": "136.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome120", "version": "120.0.0.0", "brand": "chrome"},
    {"impersonate": "edge101", "version": "101.0.1210.47", "brand": "edge"},
]
# device flow 有限并发：2 路并行换票，限流时自动退回更保守节奏
# （全串行太慢；无上限又容易 TLS/rate_limited 把成功率打穿）
_DEVICE_FLOW_MAX_CONCURRENT = 2
_DEVICE_FLOW_SEM = threading.Semaphore(_DEVICE_FLOW_MAX_CONCURRENT)
# 全局冷却：遇到 rate_limited 后，后续 device flow 至少隔这么久
_device_flow_cooldown_until = 0.0
_device_flow_cooldown_lock = threading.Lock()
# 成功后的轻冷却：压连打限流，又别像旧 2s 那样白白垫时间
_DEVICE_FLOW_SUCCESS_COOLDOWN = 0.6
# 是否在 device approve 后轮询 token。默认开启（生产要最终换到 token）。
# 仅诊断「假批准」时设 GROK_DEVICE_FLOW_ISSUE_TOKEN=0 跳过换票。
DEVICE_FLOW_ISSUE_TOKEN = os.environ.get("GROK_DEVICE_FLOW_ISSUE_TOKEN", "1").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
# Action ID 缓存：页面发版后 id 会变，过长缓存会让注册 server action 打空
_ACTION_CACHE_TTL = int(os.environ.get("GROK_ACTION_CACHE_TTL", str(30 * 60)))  # 默认 30 分钟

# x.ai 2026-10 起把「发码/验码」从 grpc-web 迁到 REST JSON：
#   POST /api/auth/send-verification-code  {email, castleRequestToken}
#   POST /api/auth/sign-up/verify-email    {email, code}
# 旧 grpc-web 端点（auth_mgmt.AuthManagement.CreateEmailValidationCode）还在，
# 但会返回 grpc-status:0 却**不再真的发信**——这正是「协议发码收不到邮箱」的根因。
# 新接口要求 castle token 与页面的会话 cookie（gb_anon_id / xai_anon_id / cf_clearance…）
# 成对出现，所以协议模式需要先用浏览器 mint castle，再把 cookie 灌回 HTTP 会话。
AUTH_CODE_SEND_PATH = "/api/auth/send-verification-code"
AUTH_CODE_VERIFY_PATH = "/api/auth/sign-up/verify-email"
_DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def send_code_castle_enabled() -> bool:
    """发码是否先用浏览器 mint Castle（默认开；GROK_SEND_CODE_CASTLE=0 可关）。

    运行时读取环境变量：app.py 先 import grok 再 load_dotenv，
    模块级常量会读不到 .env 里的值。
    """
    raw = (os.environ.get("GROK_SEND_CODE_CASTLE") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")

# 注册路径：
#   protocol     = 协议主路径：REST /api/auth/* 发码/验码/注册
#                  （发码前用无头浏览器 mint Castle 并把页面 cookie 同步进会话）
#   same_session = 同页 castle mint + 页内 fetch（发码/验码同样走新 REST 接口）
_REGISTER_MODE_DEFAULT = "protocol"
_VALID_REGISTER_MODES = ("same_session", "protocol", "legacy", "hybrid")


def resolve_register_mode(raw: Optional[str] = None) -> str:
    """归一化注册模式。legacy/hybrid 等同 protocol。"""
    m = (raw if raw is not None else os.environ.get("GROK_REGISTER_MODE") or _REGISTER_MODE_DEFAULT)
    m = str(m or "").strip().lower()
    if m in ("same_session", "ss", "clean", "same-session", "samesession"):
        return "same_session"
    if m in ("protocol", "legacy", "hybrid", "curl", "old"):
        return "protocol"
    return _REGISTER_MODE_DEFAULT


# same_session 指纹地区（locale/timezone）
# 关键规则（对齐 F:\tool\grokzhuce standalone）：
#   先探当前代理出口 IP/国家 → 指纹只在同国家簇内轮 OS/次要 tag
#   禁止 HK 出口配 JP locale / US IP 配 AU 时区（IP↔locale 错配会抬 MARKED）
_SS_FP_REGIONS = [
    {"tag": "US-W", "locale": "en-US", "timezone": "America/Los_Angeles", "fp_os": "windows"},
    {"tag": "US-E", "locale": "en-US", "timezone": "America/New_York", "fp_os": "windows"},
    {"tag": "US-C", "locale": "en-US", "timezone": "America/Chicago", "fp_os": "macos"},
    {"tag": "US-DEN", "locale": "en-US", "timezone": "America/Denver", "fp_os": "windows"},
    {"tag": "US-PHX", "locale": "en-US", "timezone": "America/Phoenix", "fp_os": "macos"},
    {"tag": "US-SEA", "locale": "en-US", "timezone": "America/Los_Angeles", "fp_os": "macos"},
    {"tag": "CA", "locale": "en-CA", "timezone": "America/Toronto", "fp_os": "macos"},
    {"tag": "CA-W", "locale": "en-CA", "timezone": "America/Vancouver", "fp_os": "windows"},
    {"tag": "GB", "locale": "en-GB", "timezone": "Europe/London", "fp_os": "windows"},
    {"tag": "IE", "locale": "en-IE", "timezone": "Europe/Dublin", "fp_os": "macos"},
    {"tag": "DE", "locale": "de-DE", "timezone": "Europe/Berlin", "fp_os": "windows"},
    {"tag": "DE-MUC", "locale": "de-DE", "timezone": "Europe/Berlin", "fp_os": "macos"},
    {"tag": "FR", "locale": "fr-FR", "timezone": "Europe/Paris", "fp_os": "windows"},
    {"tag": "NL", "locale": "nl-NL", "timezone": "Europe/Amsterdam", "fp_os": "macos"},
    {"tag": "ES", "locale": "es-ES", "timezone": "Europe/Madrid", "fp_os": "windows"},
    {"tag": "IT", "locale": "it-IT", "timezone": "Europe/Rome", "fp_os": "macos"},
    {"tag": "SE", "locale": "sv-SE", "timezone": "Europe/Stockholm", "fp_os": "windows"},
    {"tag": "PL", "locale": "pl-PL", "timezone": "Europe/Warsaw", "fp_os": "windows"},
    {"tag": "CH", "locale": "de-CH", "timezone": "Europe/Zurich", "fp_os": "macos"},
    {"tag": "JP", "locale": "ja-JP", "timezone": "Asia/Tokyo", "fp_os": "windows"},
    {"tag": "JP-OSK", "locale": "ja-JP", "timezone": "Asia/Tokyo", "fp_os": "macos"},
    {"tag": "KR", "locale": "ko-KR", "timezone": "Asia/Seoul", "fp_os": "windows"},
    {"tag": "TW", "locale": "zh-TW", "timezone": "Asia/Taipei", "fp_os": "macos"},
    {"tag": "HK", "locale": "zh-HK", "timezone": "Asia/Hong_Kong", "fp_os": "windows"},
    {"tag": "SG", "locale": "en-SG", "timezone": "Asia/Singapore", "fp_os": "windows"},
    {"tag": "SG-M", "locale": "en-SG", "timezone": "Asia/Singapore", "fp_os": "macos"},
    {"tag": "MY", "locale": "en-MY", "timezone": "Asia/Kuala_Lumpur", "fp_os": "windows"},
    {"tag": "IN", "locale": "en-IN", "timezone": "Asia/Kolkata", "fp_os": "windows"},
    {"tag": "AU", "locale": "en-AU", "timezone": "Australia/Sydney", "fp_os": "windows"},
    {"tag": "AU-MEL", "locale": "en-AU", "timezone": "Australia/Melbourne", "fp_os": "macos"},
    {"tag": "AU-PER", "locale": "en-AU", "timezone": "Australia/Perth", "fp_os": "windows"},
    {"tag": "NZ", "locale": "en-NZ", "timezone": "Pacific/Auckland", "fp_os": "macos"},
    {"tag": "BR", "locale": "pt-BR", "timezone": "America/Sao_Paulo", "fp_os": "windows"},
    {"tag": "MX", "locale": "es-MX", "timezone": "America/Mexico_City", "fp_os": "macos"},
]
_SS_FP_OS_POOL = ("windows", "macos")

# ISO / 时区 → 国家簇（出口对齐用；与 standalone_same_session_n 同源）
_SS_CC_FAMILY: dict[str, str] = {
    "JP": "jp", "AU": "au", "US": "us", "KR": "kr", "SG": "sg",
    "TW": "tw", "MY": "my", "HK": "hk", "GB": "gb", "UK": "gb",
    "CA": "ca", "DE": "de", "FR": "fr", "NL": "nl", "IE": "ie",
    "ES": "es", "IT": "it", "SE": "se", "PL": "pl", "CH": "ch",
    "IN": "in", "NZ": "nz", "BR": "br", "MX": "mx",
}
_SS_TZ_FAMILY: dict[str, str] = {
    "asia/tokyo": "jp", "asia/osaka": "jp",
    "australia/sydney": "au", "australia/melbourne": "au", "australia/perth": "au",
    "america/los_angeles": "us", "america/new_york": "us", "america/chicago": "us",
    "america/denver": "us", "america/phoenix": "us",
    "america/toronto": "ca", "america/vancouver": "ca",
    "asia/seoul": "kr", "asia/singapore": "sg", "asia/taipei": "tw",
    "asia/kuala_lumpur": "my", "asia/hong_kong": "hk", "asia/kolkata": "in",
    "europe/london": "gb", "europe/dublin": "ie", "europe/berlin": "de",
    "europe/paris": "fr", "europe/amsterdam": "nl", "europe/madrid": "es",
    "europe/rome": "it", "europe/stockholm": "se", "europe/warsaw": "pl",
    "europe/zurich": "ch", "pacific/auckland": "nz",
    "america/sao_paulo": "br", "america/mexico_city": "mx",
}
_SS_FAMILY_DEFAULTS: dict[str, dict[str, str]] = {
    "jp": {"tag": "JP-LOCAL", "locale": "ja-JP", "timezone": "Asia/Tokyo"},
    "au": {"tag": "AU-LOCAL", "locale": "en-AU", "timezone": "Australia/Sydney"},
    "us": {"tag": "US-LOCAL", "locale": "en-US", "timezone": "America/Los_Angeles"},
    "kr": {"tag": "KR-LOCAL", "locale": "ko-KR", "timezone": "Asia/Seoul"},
    "sg": {"tag": "SG-LOCAL", "locale": "en-SG", "timezone": "Asia/Singapore"},
    "tw": {"tag": "TW-LOCAL", "locale": "zh-TW", "timezone": "Asia/Taipei"},
    "my": {"tag": "MY-LOCAL", "locale": "en-MY", "timezone": "Asia/Kuala_Lumpur"},
    "hk": {"tag": "HK-LOCAL", "locale": "zh-HK", "timezone": "Asia/Hong_Kong"},
    "gb": {"tag": "GB-LOCAL", "locale": "en-GB", "timezone": "Europe/London"},
    "ca": {"tag": "CA-LOCAL", "locale": "en-CA", "timezone": "America/Toronto"},
    "de": {"tag": "DE-LOCAL", "locale": "de-DE", "timezone": "Europe/Berlin"},
    "fr": {"tag": "FR-LOCAL", "locale": "fr-FR", "timezone": "Europe/Paris"},
    "nl": {"tag": "NL-LOCAL", "locale": "nl-NL", "timezone": "Europe/Amsterdam"},
    "ie": {"tag": "IE-LOCAL", "locale": "en-IE", "timezone": "Europe/Dublin"},
    "es": {"tag": "ES-LOCAL", "locale": "es-ES", "timezone": "Europe/Madrid"},
    "it": {"tag": "IT-LOCAL", "locale": "it-IT", "timezone": "Europe/Rome"},
    "se": {"tag": "SE-LOCAL", "locale": "sv-SE", "timezone": "Europe/Stockholm"},
    "pl": {"tag": "PL-LOCAL", "locale": "pl-PL", "timezone": "Europe/Warsaw"},
    "ch": {"tag": "CH-LOCAL", "locale": "de-CH", "timezone": "Europe/Zurich"},
    "in": {"tag": "IN-LOCAL", "locale": "en-IN", "timezone": "Asia/Kolkata"},
    "nz": {"tag": "NZ-LOCAL", "locale": "en-NZ", "timezone": "Pacific/Auckland"},
    "br": {"tag": "BR-LOCAL", "locale": "pt-BR", "timezone": "America/Sao_Paulo"},
    "mx": {"tag": "MX-LOCAL", "locale": "es-MX", "timezone": "America/Mexico_City"},
}
# 按代理 spec 缓存出口探测（切代理后各自独立）
_SS_EGRESS_LOCK = threading.Lock()
_SS_EGRESS_BY_PROXY: dict[str, dict[str, Any]] = {}
_SS_EGRESS_PROBE_COUNT: dict[str, int] = {}  # 每代理探测次数，配合 EVERY
_SS_VIEWPORT_BASES = (
    (1280, 720),
    (1280, 800),
    (1360, 768),
    (1366, 768),
    (1400, 900),
    (1440, 900),
    (1470, 956),
    (1512, 982),  # mac-ish
    (1536, 864),
    (1600, 900),
    (1680, 1050),
    (1728, 1117),
    (1792, 1120),
    (1920, 1080),
    (1920, 1200),
    (2048, 1152),
    (2560, 1440),
)
# 近期指纹签名去重：避免同批连号撞同一 locale/OS/时区簇
_SS_RECENT_FP_LOCK = threading.Lock()
_SS_RECENT_FP_SIGS: deque = deque(maxlen=48)


def _ss_split_proxy_lines(raw: str) -> list[str]:
    """代理池拆行：换行/逗号/分号；去 # 注释与空行，去重保序。"""
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    parts: list[str] = []
    for chunk in re.split(r"[\n,;]+", text):
        line = (chunk or "").strip()
        if not line or line.startswith("#"):
            continue
        parts.append(line)
    seen: set[str] = set()
    out: list[str] = []
    for p in parts:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _ss_load_proxy_pool() -> list[str]:
    """
    加载代理池。优先级：
      1) GROK_PROXY_LIST（多行/分号）
      2) GROK_PROXY / XAI_PROXY / SAME_SESSION_PROXY / GROK_SAME_SESSION_PROXY
      3) STANDALONE_LOCAL_PROXY / LOCAL_PROXY
      4) 空列表 = 直连（不再默认塞 127.0.0.1:7897，避免误绑）
    """
    pool = _ss_split_proxy_lines(os.environ.get("GROK_PROXY_LIST") or "")
    if pool:
        return pool
    for key in (
        "GROK_PROXY",
        "XAI_PROXY",
        "SAME_SESSION_PROXY",
        "GROK_SAME_SESSION_PROXY",
        "STANDALONE_LOCAL_PROXY",
        "LOCAL_PROXY",
    ):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            one = _ss_split_proxy_lines(raw)
            if one:
                return one
            return [raw]
    return []


def _ss_local_proxy_spec() -> str:
    """同会话当前代理：池首条；无池则空（直连）。"""
    pool = _ss_load_proxy_pool()
    if pool:
        return pool[0]
    return ""


def _ss_mask_proxy(spec: str) -> str:
    """日志脱敏：藏密码。"""
    s = (spec or "").strip()
    if not s:
        return "(direct)"
    try:
        if "@" in s:
            return s.split("@", 1)[-1]
        parts = s.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            return f"{parts[0]}:{parts[1]}:***"
        if "://" in s and "@" in s:
            return s.split("@", 1)[-1]
    except Exception:
        pass
    return s if len(s) <= 64 else (s[:28] + "…" + s[-12:])


def _ss_proxy_switch_limit() -> int:
    """
    deny 后连续切换代理次数上限；触顶进入冷却。
    GROK_SS_PROXY_SWITCH_LIMIT / STANDALONE_PROXY_SWITCH；默认 3；0=不切代理只停。
    """
    raw = (
        os.environ.get("GROK_SS_PROXY_SWITCH_LIMIT")
        or os.environ.get("STANDALONE_PROXY_SWITCH")
        or "3"
    ).strip().lower()
    if raw in ("0", "off", "false", "no", "none"):
        return 0
    try:
        return max(0, int(raw))
    except Exception:
        return 3


def _ss_cooldown_sec() -> float:
    """
    连续切代理仍 deny 后的冷却秒数。
    GROK_SS_COOLDOWN_SEC / STANDALONE_COOLDOWN_SEC；默认 60；0=不冷却直接继续（仍会重置切换计数）。
    """
    raw = (
        os.environ.get("GROK_SS_COOLDOWN_SEC")
        or os.environ.get("STANDALONE_COOLDOWN_SEC")
        or "60"
    ).strip().lower()
    if raw in ("off", "false", "no", "none"):
        return 0.0
    try:
        return max(0.0, float(raw))
    except Exception:
        return 60.0


def _ss_fp_sig(fp: dict[str, Any]) -> str:
    """粗粒度签名：区 + OS + 时区 + 时序档（分辨率故意不进，避免过严）。"""
    return "|".join(
        [
            str(fp.get("tag") or ""),
            str(fp.get("fp_os") or ""),
            str(fp.get("timezone") or ""),
            str(fp.get("locale") or ""),
            str(fp.get("timing") or ""),
        ]
    )


def _ss_region_family(tag_or_text: str) -> str:
    """粗分国家簇，避免 JP 出口配 AU locale（IP/时区错配）。"""
    b = (tag_or_text or "").lower().replace("_", " ").replace("-", " ")
    checks = (
        ("jp", ("jp", "tokyo", "osaka", "japan")),
        ("au", ("au", "sydney", "melbourne", "perth", "australia")),
        ("us", (" us", "united states", "los angeles", "new york", "america/", "chicago", "denver", "phoenix")),
        ("kr", ("kr", "seoul", "korea")),
        ("sg", ("sg", "singapore")),
        ("tw", ("tw", "taipei", "taiwan")),
        ("my", ("my", "kuala", "malaysia")),
        ("hk", ("hk", "hong kong", "hongkong")),
        ("gb", ("gb", "london", "uk", "britain")),
        ("ca", ("ca", "toronto", "vancouver", "canada")),
        ("de", ("de", "berlin", "germany")),
        ("fr", ("fr", "paris", "france")),
        ("nl", ("nl", "amsterdam", "netherlands")),
        ("ie", ("ie", "dublin", "ireland")),
        ("es", ("es", "madrid", "spain")),
        ("it", ("it", "rome", "italy")),
        ("se", ("se", "stockholm", "sweden")),
        ("pl", ("pl", "warsaw", "poland")),
        ("ch", ("ch", "zurich", "switzerland")),
        ("in", ("in", "kolkata", "india", "mumbai")),
        ("nz", ("nz", "auckland", "zealand")),
        ("br", ("br", "sao paulo", "brazil")),
        ("mx", ("mx", "mexico")),
    )
    padded = f" {b} "
    # us 特判：开头 us / 单词 us
    if b.startswith("us") or " us " in padded or "united states" in b:
        return "us"
    for fam, keys in checks:
        if fam == "us":
            continue
        for k in keys:
            if k in b:
                return fam
    return ""


def _ss_family_from_egress(cc: str = "", tz: str = "", city: str = "") -> str:
    cc_u = (cc or "").strip().upper()
    if cc_u in _SS_CC_FAMILY:
        return _SS_CC_FAMILY[cc_u]
    tz_l = (tz or "").strip().lower()
    if tz_l in _SS_TZ_FAMILY:
        return _SS_TZ_FAMILY[tz_l]
    return _ss_region_family(f"{cc} {tz} {city}")


def _ss_proxy_hint_family(proxy_spec: str) -> str:
    """
    从代理字符串猜国家簇（1024proxy region-XX / 用户名含 JP 等）。
    探测失败时的软兜底，不能替代真实出口探测。
    """
    s = (proxy_spec or "").strip()
    if not s:
        return ""
    # region-US / region-JP 常见于 1024proxy user
    m = re.search(r"region[-_]?([A-Za-z]{2})", s, re.I)
    if m:
        return _ss_family_from_egress(m.group(1).upper(), "", "")
    return _ss_region_family(s)


def _ss_fp_pool_for_family(
    fam: str, egress: Optional[dict[str, Any]] = None
) -> list[dict[str, Any]]:
    """同国家簇指纹池；无匹配则用探测 tz/locale 合成 win+mac 两条。"""
    fam = (fam or "").strip().lower()
    if fam:
        same = [
            fr
            for fr in _SS_FP_REGIONS
            if _ss_region_family(
                f"{fr.get('tag') or ''} {fr.get('timezone') or ''} {fr.get('locale') or ''}"
            )
            == fam
        ]
        if same:
            return list(same)
    eg = egress or {}
    base = dict(_SS_FAMILY_DEFAULTS.get(fam) or {})
    tz = (eg.get("timezone") or base.get("timezone") or "America/Los_Angeles").strip()
    loc = (base.get("locale") or "en-US").strip()
    tag = base.get("tag") or f"EG-{(eg.get('cc') or 'XX')}"
    if not fam and eg.get("timezone"):
        fam2 = _ss_family_from_egress(
            str(eg.get("cc") or ""), str(eg.get("timezone") or ""), ""
        )
        if fam2 and fam2 in _SS_FAMILY_DEFAULTS:
            loc = _SS_FAMILY_DEFAULTS[fam2]["locale"]
            tag = _SS_FAMILY_DEFAULTS[fam2]["tag"]
            if not eg.get("timezone"):
                tz = _SS_FAMILY_DEFAULTS[fam2]["timezone"]
    return [
        {"tag": tag, "locale": loc, "timezone": tz, "fp_os": "windows"},
        {"tag": f"{tag}-MAC", "locale": loc, "timezone": tz, "fp_os": "macos"},
    ]


def _ss_detect_egress(
    proxy_spec: str = "",
    *,
    force: bool = False,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> dict[str, Any]:
    """
    经当前注册代理探测真实出口 IP/国家/时区。
    批内按 proxy_spec 缓存；切代理后各自独立。
    覆盖：STANDALONE_EGRESS_CC / TZ / IP 可手填跳过探测。
    """
    key = (proxy_spec or "").strip() or "(direct)"
    with _SS_EGRESS_LOCK:
        cached = _SS_EGRESS_BY_PROXY.get(key)
        if cached is not None and not force:
            return dict(cached)

    env_cc = (os.environ.get("STANDALONE_EGRESS_CC") or os.environ.get("GROK_SS_EGRESS_CC") or "").strip().upper()
    env_tz = (os.environ.get("STANDALONE_EGRESS_TZ") or os.environ.get("GROK_SS_EGRESS_TZ") or "").strip()
    env_ip = (os.environ.get("STANDALONE_EGRESS_IP") or os.environ.get("GROK_SS_EGRESS_IP") or "").strip()
    if env_cc or env_tz:
        fam = _ss_family_from_egress(env_cc, env_tz, "")
        info: dict[str, Any] = {
            "ok": True,
            "source": "env",
            "ip": env_ip or "?",
            "cc": env_cc,
            "country": env_cc,
            "city": "",
            "timezone": env_tz
            or (_SS_FAMILY_DEFAULTS.get(fam) or {}).get("timezone", ""),
            "family": fam,
            "proxy": key,
        }
        with _SS_EGRESS_LOCK:
            _SS_EGRESS_BY_PROXY[key] = dict(info)
        return info

    info = {
        "ok": False,
        "source": "",
        "ip": "",
        "cc": "",
        "country": "",
        "city": "",
        "timezone": "",
        "family": "",
        "proxy": key,
        "error": "",
    }
    proxies = None
    raw = (proxy_spec or "").strip()
    if raw:
        try:
            parsed = parse_proxy_spec(raw) or {}
            url = (parsed.get("server_url") or parsed.get("server") or "").strip()
            if url:
                proxies = {"http": url, "https": url}
        except Exception as e:
            info["error"] = f"parse:{e}"[:80]

    try:
        from curl_cffi import requests as creq

        # 复用 app 侧多源探测（mayips → ip-api → cf）
        try:
            from app import _probe_egress_via_proxy

            eg = _probe_egress_via_proxy(creq, proxies=proxies, timeout=8.0)
        except Exception:
            # 轻量自备：ip-api
            eg = {"ok": False, "error": "probe_import_fail"}
            try:
                r = creq.get(
                    "http://ip-api.com/json/?fields=status,message,country,countryCode,city,timezone,query",
                    proxies=proxies,
                    timeout=8,
                    impersonate="chrome131",
                )
                data = r.json() if hasattr(r, "json") else {}
                if str(data.get("status") or "").lower() == "success":
                    eg = {
                        "ok": True,
                        "source": "ip-api",
                        "ip": str(data.get("query") or ""),
                        "cc": str(data.get("countryCode") or "").upper(),
                        "country": str(data.get("country") or ""),
                        "city": str(data.get("city") or ""),
                        "timezone": str(data.get("timezone") or ""),
                    }
            except Exception as e2:
                eg = {"ok": False, "error": str(e2)[:120]}

        if eg.get("ok"):
            info.update(
                {
                    "ok": True,
                    "source": str(eg.get("source") or "probe"),
                    "ip": str(eg.get("ip") or ""),
                    "cc": str(eg.get("cc") or "").upper(),
                    "country": str(eg.get("country") or ""),
                    "city": str(eg.get("city") or ""),
                    "timezone": str(eg.get("timezone") or ""),
                    "error": "",
                }
            )
        else:
            info["error"] = str(eg.get("error") or "egress fail")[:160]
    except Exception as e:
        info["error"] = str(e)[:160]

    if info.get("ok"):
        fam = _ss_family_from_egress(
            str(info.get("cc") or ""),
            str(info.get("timezone") or ""),
            str(info.get("city") or ""),
        )
        # 代理串 hint 兜底（探测无 cc 时）
        if not fam:
            fam = _ss_proxy_hint_family(raw)
        info["family"] = fam
        if not info.get("timezone") and fam and fam in _SS_FAMILY_DEFAULTS:
            info["timezone"] = _SS_FAMILY_DEFAULTS[fam]["timezone"]

    with _SS_EGRESS_LOCK:
        prev_ok = _SS_EGRESS_BY_PROXY.get(key)
        prev_ok = (
            dict(prev_ok)
            if isinstance(prev_ok, dict) and prev_ok.get("ok")
            else None
        )
        # 强刷失败不覆盖上一份成功缓存（防偶发失败 → 全球乱跳）
        if info.get("ok") or not prev_ok:
            _SS_EGRESS_BY_PROXY[key] = dict(info)
        else:
            info = dict(prev_ok)
            info["stale"] = True
            info["refresh_error"] = str(info.get("error") or "")
            _SS_EGRESS_BY_PROXY[key] = dict(info)
        _SS_EGRESS_PROBE_COUNT[key] = int(_SS_EGRESS_PROBE_COUNT.get(key) or 0) + 1

    if log_fn:
        try:
            if info.get("ok"):
                log_fn(
                    f"出口对齐 · {info.get('ip') or '?'} · "
                    f"{info.get('cc') or '?'} {info.get('city') or ''} · "
                    f"tz={info.get('timezone') or '?'} · "
                    f"family={info.get('family') or 'unknown'} · "
                    f"via {info.get('source')} · px={_ss_mask_proxy(raw)}",
                    "info",
                )
            else:
                log_fn(
                    f"出口探测失败 · {info.get('error') or '?'} · "
                    f"px={_ss_mask_proxy(raw)} · 指纹将全球轮（可设 STANDALONE_EGRESS_CC）",
                    "warn",
                )
        except Exception:
            pass
    return info


def _ss_invalidate_egress(proxy_spec: str = "") -> None:
    """切代理后清该条缓存，下次强制复探。"""
    key = (proxy_spec or "").strip() or "(direct)"
    with _SS_EGRESS_LOCK:
        _SS_EGRESS_BY_PROXY.pop(key, None)


def _ss_aligned_region_pool(
    proxy_spec: str = "",
    idx: int = 0,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    按当前代理出口锁指纹池（同国家簇）。
    返回 (pool, egress_info)。
    STANDALONE_LOCAL_ALIGN=0 / GROK_SS_FP_ALIGN=0 可关（调试用全球轮）。
    """
    align_off = (
        os.environ.get("GROK_SS_FP_ALIGN")
        or os.environ.get("STANDALONE_LOCAL_ALIGN")
        or "1"
    ).strip().lower() in ("0", "off", "false", "no")

    force_env = (
        os.environ.get("STANDALONE_EGRESS_REFRESH")
        or os.environ.get("GROK_SS_EGRESS_REFRESH")
        or ""
    ).strip().lower() in ("1", "true", "yes", "on")
    try:
        every_n = int(
            (
                os.environ.get("STANDALONE_EGRESS_EVERY")
                or os.environ.get("GROK_SS_EGRESS_EVERY")
                or "3"
            ).strip()
            or "3"
        )
    except ValueError:
        every_n = 3
    every_n = max(0, every_n)
    key = (proxy_spec or "").strip() or "(direct)"
    with _SS_EGRESS_LOCK:
        prev = dict(_SS_EGRESS_BY_PROXY.get(key) or {})
        n_probe = int(_SS_EGRESS_PROBE_COUNT.get(key) or 0)
    do_force = bool(force_env) or (
        every_n > 0 and (idx <= 1 or n_probe == 0 or (idx - 1) % every_n == 0)
    )
    # 无缓存必须探
    if not prev:
        do_force = True

    if align_off:
        return list(_SS_FP_REGIONS), {"ok": False, "align_off": True, "family": ""}

    eg = _ss_detect_egress(proxy_spec, force=do_force, log_fn=log_fn if do_force else None)
    if do_force and eg.get("ok") and prev.get("ok") and log_fn:
        old_ip = str(prev.get("ip") or "")
        new_ip = str(eg.get("ip") or "")
        old_fam = str(prev.get("family") or "")
        new_fam = str(eg.get("family") or "")
        try:
            if old_ip and new_ip and old_ip != new_ip:
                log_fn(
                    f"出口漂移 · {old_ip}({old_fam or '?'}) → {new_ip}({new_fam or '?'}) · "
                    f"指纹簇重锁 · idx={idx}",
                    "warn" if old_fam and new_fam and old_fam != new_fam else "info",
                )
            elif old_fam and new_fam and old_fam != new_fam:
                log_fn(
                    f"出口国家簇变 · {old_fam} → {new_fam} · 指纹重锁 · idx={idx}",
                    "warn",
                )
        except Exception:
            pass

    if not eg.get("ok"):
        # 探测失败：代理串 hint → 仍尽量锁簇；都没有才全球轮
        hint = _ss_proxy_hint_family(proxy_spec)
        if hint:
            pool = _ss_fp_pool_for_family(hint, eg)
            eg = dict(eg)
            eg["family"] = hint
            eg["family_source"] = "proxy_hint"
            return pool, eg
        return list(_SS_FP_REGIONS), eg

    fam = str(eg.get("family") or "")
    pool = _ss_fp_pool_for_family(fam, eg)
    if not pool:
        pool = list(_SS_FP_REGIONS)
    return pool, eg


def _ss_pick_fp(
    idx: int = 0,
    proxy_spec: str = "",
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> dict[str, Any]:
    """
    打散指纹：OS/分辨率/时序轮转 + 近期去重。
    地区/时区按当前代理出口国家簇锁定（防 IP↔locale 乱跳）。
    """
    pool, eg = _ss_aligned_region_pool(proxy_spec, idx=idx, log_fn=log_fn)
    n = len(pool) or 1
    # 同簇内 jump：只换 OS/次要 tag，不跳国
    jump_p = 0.55
    try:
        jump_p = float(
            (
                os.environ.get("GROK_SS_FP_JUMP_PROB")
                or os.environ.get("STANDALONE_FP_JUMP")
                or "0.55"
            ).strip()
            or "0.55"
        )
    except ValueError:
        jump_p = 0.55
    # 同簇池小时 jump 无害；全球池时 jump 仍危险——但 align 开着时 pool 已是同簇
    jump_p = max(0.0, min(0.95, jump_p))

    def _one_region() -> dict[str, Any]:
        if n <= 1:
            return dict(pool[0])
        if idx and n:
            base = (max(0, int(idx) - 1) * 5 + random.randint(0, 4)) % n
            if random.random() < jump_p:
                return dict(random.choice(pool))
            return dict(pool[base])
        return dict(random.choice(pool))

    timing_env = (
        os.environ.get("STANDALONE_TIMING")
        or os.environ.get("GROK_SS_TIMING")
        or "rotate"
    ).strip().lower()

    def _one_timing() -> str:
        if timing_env in ("rotate", "random", "rand", "mix", ""):
            return random.choices(
                ["turbo", "fast", "normal", "human"],
                weights=[32, 38, 22, 8],
                k=1,
            )[0]
        if timing_env in ("turbo", "fast", "normal", "human", "slow"):
            if random.random() < 0.35:
                return random.choice(["turbo", "fast", "normal", "human"])
            return timing_env
        return random.choice(["turbo", "fast", "normal"])

    os_env = (
        os.environ.get("STANDALONE_FP_OS") or os.environ.get("GROK_SS_FP_OS") or ""
    ).strip().lower()

    def _one_os(region: dict[str, Any]) -> str:
        if os_env in ("win", "windows"):
            return "windows"
        if os_env in ("mac", "macos", "osx"):
            return "macos"
        if os_env in ("rotate", "random", "mix", "auto", ""):
            pref = str(region.get("fp_os") or "windows").strip().lower()
            if pref not in _SS_FP_OS_POOL:
                pref = "windows"
            if random.random() < 0.55:
                return random.choice(list(_SS_FP_OS_POOL))
            return pref
        return "windows"

    hum_env = (
        os.environ.get("STANDALONE_HUMANIZE")
        or os.environ.get("GROK_SAME_SESSION_HUMANIZE")
        or ""
    ).strip().lower()

    def _one_humanize(timing: str) -> bool:
        if hum_env in ("1", "true", "yes", "on"):
            return True
        if hum_env in ("0", "false", "no", "off"):
            return False
        if timing in ("turbo", "fast"):
            return random.random() < 0.28
        if timing == "human":
            return True
        return random.random() < 0.75

    fam = str(eg.get("family") or "")
    cc = str(eg.get("cc") or "").upper()
    eg_ip = str(eg.get("ip") or "")

    fp: dict[str, Any] = {}
    for _try in range(8):
        region = _one_region()
        timing = _one_timing()
        fp_os = _one_os(region)
        vw, vh = random.choice(_SS_VIEWPORT_BASES)
        vw = max(1180, min(2560, vw + random.randint(-36, 40)))
        vh = max(700, min(1600, vh + random.randint(-28, 32)))
        if random.random() < 0.12:
            vw = max(1200, vw + random.randint(-80, 120))
            vh = max(720, int(vw * random.uniform(0.55, 0.72)))
        base_tag = str(region.get("tag") or "LOCAL")
        # tag 带出口 cc，方便日志对照
        if eg.get("ok") and cc and cc not in base_tag.upper():
            tag = f"{base_tag}@{cc}"
        else:
            tag = base_tag
        cand = {
            "tag": tag,
            "locale": region.get("locale") or "en-US",
            "timezone": region.get("timezone") or "America/Los_Angeles",
            "fp_os": fp_os,
            "timing": timing,
            "viewport": {"width": int(vw), "height": int(vh)},
            "humanize": _one_humanize(timing),
            "egress_ip": eg_ip,
            "egress_cc": cc,
            "egress_family": fam,
            "egress_tz": str(eg.get("timezone") or ""),
        }
        # 探测到更准的 tz 时，同簇内可微调（不跨族）
        if eg.get("ok") and eg.get("timezone") and fam:
            eg_tz = str(eg.get("timezone") or "")
            if _ss_family_from_egress(cc, eg_tz, "") == fam and eg_tz:
                # 50% 用探测 tz（城市级更贴），其余用池内标准 tz
                if random.random() < 0.45:
                    cand["timezone"] = eg_tz
        sig = _ss_fp_sig(cand)
        with _SS_RECENT_FP_LOCK:
            recent = set(_SS_RECENT_FP_SIGS)
            coarse = f"{cand['tag']}|{cand['fp_os']}|{cand['timezone']}"
            coarse_hit = any(
                s.startswith(coarse + "|") or s.startswith(coarse)
                for s in list(_SS_RECENT_FP_SIGS)[-16:]
            )
            if sig in recent or coarse_hit:
                continue
            _SS_RECENT_FP_SIGS.append(sig)
            fp = cand
            break
    if not fp:
        region = _one_region()
        timing = _one_timing()
        vw, vh = random.choice(_SS_VIEWPORT_BASES)
        vw = max(1200, vw + random.randint(-20, 20))
        vh = max(700, vh + random.randint(-16, 16))
        base_tag = str(region.get("tag") or "LOCAL")
        tag = f"{base_tag}@{cc}" if (eg.get("ok") and cc and cc not in base_tag.upper()) else base_tag
        fp = {
            "tag": tag,
            "locale": region.get("locale") or "en-US",
            "timezone": region.get("timezone") or "America/Los_Angeles",
            "fp_os": _one_os(region),
            "timing": timing,
            "viewport": {"width": int(vw), "height": int(vh)},
            "humanize": _one_humanize(timing),
            "egress_ip": eg_ip,
            "egress_cc": cc,
            "egress_family": fam,
            "egress_tz": str(eg.get("timezone") or ""),
        }
        with _SS_RECENT_FP_LOCK:
            _SS_RECENT_FP_SIGS.append(_ss_fp_sig(fp))
    return fp


def _ss_deny_break_n() -> int:
    """
    连续 risk MARKED/deny 熔断阈值（对齐 standalone）。
    默认 3：同出口 Castle deny 簇打开后继续硬刚只会空烧。
    覆盖：GROK_SS_DENY_BREAK / STANDALONE_DENY_BREAK；0/off 关闭。
    """
    raw = (
        os.environ.get("GROK_SS_DENY_BREAK")
        or os.environ.get("STANDALONE_DENY_BREAK")
        or "3"
    ).strip().lower()
    if raw in ("0", "off", "false", "no", "none"):
        return 0
    try:
        return max(0, int(raw))
    except Exception:
        return 3


def _ss_inter_account_delay(workers: int = 1, consecutive_deny: int = 0) -> float:
    """
    号间抖动秒数：压同出口短时 $registration 密度。
    GROK_SS_JITTER_MS=800-2800 或 单值；0 关闭。
    连续 MARKED 时指数加冷（对齐 standalone）。
    """
    raw = (
        os.environ.get("GROK_SS_JITTER_MS")
        or os.environ.get("STANDALONE_SS_JITTER_MS")
        or "900-3200"
    ).strip().lower()
    if raw in ("0", "off", "no", "false", "none", ""):
        # 空默认仍给一点底噪
        if raw == "":
            lo, hi = 900, 3200
        else:
            base = 0.0
            if consecutive_deny > 0:
                base += min(20.0, 4.0 * (2 ** (max(0, consecutive_deny) - 1)))
            return max(0.0, base)
    else:
        try:
            if "-" in raw:
                a, b = raw.split("-", 1)
                lo, hi = int(a.strip()), int(b.strip())
            else:
                lo = hi = int(raw)
        except ValueError:
            lo, hi = 900, 3200
    if hi < lo:
        lo, hi = hi, lo
    lo = max(0, lo)
    hi = max(lo, hi)
    # 并发越高，单号再多等一点，摊平出口
    w = max(1, int(workers or 1))
    bump = min(1800, 180 * max(0, w - 1))
    ms = random.randint(lo, hi + bump)
    base = ms / 1000.0
    # 连续 deny：指数加冷（1→+4s, 2→+8s, 3→+16s… 封顶 +20s）
    if consecutive_deny > 0:
        base += min(20.0, 4.0 * (2 ** (max(0, int(consecutive_deny)) - 1)))
    return max(0.0, base)


def get_random_chrome_profile():
    profile = random.choice(CHROME_PROFILES)
    if profile.get("brand") == "edge":
        chrome_major = profile["version"].split(".")[0]
        chrome_version = f"{chrome_major}.0.0.0"
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{chrome_version} Safari/537.36 Edg/{profile['version']}"
        )
    else:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{profile['version']} Safari/537.36"
        )
    return profile["impersonate"], ua


PROXIES = {
    # "http": "http://127.0.0.1:10808",
    # "https": "http://127.0.0.1:10808"
}


def _curl_proxies_from_spec(raw: str) -> dict[str, str]:
    """把一条代理 spec 转成 curl_cffi 的 {http, https} 字典。"""
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        parsed = parse_proxy_spec(raw) or {}
        url = str(parsed.get("server_url") or parsed.get("server") or "").strip()
        return {"http": url, "https": url} if url else {}
    except Exception:
        return {}


def _configured_curl_proxies() -> dict[str, str]:
    """Resolve the registration proxy for curl_cffi without using system proxy settings."""
    if PROXIES:
        return dict(PROXIES)

    raw = (os.environ.get("GROK_PROXY") or os.environ.get("XAI_PROXY") or "").strip()
    if not raw:
        pool = (os.environ.get("GROK_PROXY_LIST") or "").strip()
        raw = next((part.strip() for part in re.split(r"[\n,;]+", pool) if part.strip()), "")
    if not raw:
        return {}

    return _curl_proxies_from_spec(raw)


def generate_random_name() -> str:
    length = random.randint(4, 6)
    return random.choice(string.ascii_uppercase) + "".join(
        random.choice(string.ascii_lowercase) for _ in range(length - 1)
    )


def generate_random_string(length: int = 15) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    """解析 JWT payload（不验签），失败返回空 dict。"""
    try:
        parts = (token or "").strip().split(".")
        if len(parts) != 3:
            return {}
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def is_auth_token_usable(token: Any, *, skew_seconds: float = 60.0) -> bool:
    """
    判断注册时缓存的 device flow token 是否还能直接写上游。
    有 access_token，且 JWT exp 未过期（留 skew 余量）才算可用。
    """
    if not isinstance(token, dict):
        return False
    access = (token.get("access_token") or token.get("key") or "").strip()
    if not access:
        return False
    payload = decode_jwt_payload(access)
    exp = payload.get("exp")
    if exp is not None:
        try:
            if float(exp) <= time.time() + float(skew_seconds):
                return False
        except (TypeError, ValueError):
            return False
    return True


def is_sso_jwt_shape(sso: str) -> bool:
    """粗检：xAI sso cookie 一般为 eyJ 开头的 JWT。"""
    s = (sso or "").strip()
    if not s or not s.startswith("eyJ"):
        return False
    parts = s.split(".")
    if len(parts) != 3:
        return False
    payload = decode_jwt_payload(s)
    return bool(payload)


def _device_flow_error_kind(err: str) -> str:
    """分类 device flow 错误，便于退避策略。"""
    e = (err or "").lower()
    if "rate_limited" in e or "rate limit" in e or "too many" in e:
        return "rate_limited"
    if "curl: (35)" in e or "tls" in e or "ssl" in e or "openssl" in e:
        return "tls"
    if (
        "timed out" in e
        or "timeout" in e
        or "curl: (28)" in e
        or "connection timed out" in e
    ):
        return "timeout"
    if "device/code" in e or "device code" in e:
        return "device_code"
    if "authorization_pending" in e or "未拿到 access_token" in e:
        return "token_poll"
    if "会话无效" in e or "非有效 jwt" in e:
        return "invalid"
    return "other"


def _device_flow_wait_seconds(err: str, attempt: int = 1) -> float:
    """按错误类型返回建议等待秒数。"""
    kind = _device_flow_error_kind(err)
    a = max(1, int(attempt))
    if kind == "rate_limited":
        return min(90.0, 18.0 * a + random.uniform(2, 6))
    if kind == "timeout":
        return min(45.0, 6.0 * a + random.uniform(1, 3))
    if kind == "tls":
        return min(30.0, 4.0 * a + random.uniform(0.5, 2))
    if kind == "device_code":
        return min(40.0, 8.0 * a)
    if kind == "token_poll":
        return min(20.0, 3.0 * a)
    return min(20.0, 3.0 * a)


def _mark_device_flow_cooldown(seconds: float) -> None:
    global _device_flow_cooldown_until
    until = time.time() + max(0.0, float(seconds))
    with _device_flow_cooldown_lock:
        if until > _device_flow_cooldown_until:
            _device_flow_cooldown_until = until


def _wait_device_flow_cooldown() -> None:
    """若处于 rate_limited 冷却期则阻塞等待。"""
    with _device_flow_cooldown_lock:
        until = float(_device_flow_cooldown_until or 0.0)
    remain = until - time.time()
    if remain > 0:
        time.sleep(min(remain, 120.0))


def _proxy_kw() -> dict:
    """Pass the configured registration proxy to curl_cffi, never ambient system proxies."""
    proxies = _configured_curl_proxies()
    return {"proxies": proxies} if proxies else {}


def _extract_signup_action_id(js_or_html: str) -> Optional[str]:
    """
    从 Next.js chunk / HTML 提取 sign-up 的 server action id。
    优先 createServerReference(\"...\", ..., \"default\")，兼容裸 7f… 哈希。
    """
    text = js_or_html or ""
    # 命名 default 的注册 action（当前页面真源）
    m = re.search(
        r'createServerReference\)?\(\s*["\']([a-f0-9]{40,44})["\'][^)]*?["\']default["\']',
        text,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'createServerReference\)?\(\s*["\'](7f[a-f0-9]{40})["\']',
        text,
    )
    if m:
        return m.group(1)
    m = re.search(r"\b(7f[a-fA-F0-9]{40})\b", text)
    if m:
        return m.group(1)
    return None


def _parse_device_consent_page(html: str, page_url: str = "") -> dict[str, str]:
    """
    从 OAuth 同意页 HTML 解析当前版本的 approve form。
    页面仍是 form POST（非 server action）；字段/action URL 以页面为准自动跟随。
    """
    out = {
        "approve_url": f"{OIDC_ISSUER}/oauth2/device/approve",
        "user_code": "",
        "principal_type": "User",
        "principal_id": "",
        "user_id": "",
    }
    text = html or ""
    try:
        soup = BeautifulSoup(text, "html.parser")
        form = None
        for f in soup.find_all("form"):
            action = (f.get("action") or "").lower()
            if "device/approve" in action or "approve" in action:
                form = f
                break
        if form is None and soup.find("form"):
            form = soup.find("form")
        if form is not None:
            action = (form.get("action") or "").strip()
            if action:
                out["approve_url"] = urljoin(page_url or f"{site_url}/", action)
            for inp in form.find_all("input"):
                name = (inp.get("name") or "").strip()
                val = inp.get("value")
                if val is None:
                    val = ""
                if name == "user_code" and val:
                    out["user_code"] = str(val)
                elif name == "principal_type" and val:
                    out["principal_type"] = str(val)
                elif name == "principal_id":
                    out["principal_id"] = str(val)
    except Exception:
        pass
    # RSC/flight 里的 userId（表单 principal_id 常为空，由前端 state 填）
    m = re.search(r'"userId":"([0-9a-fA-F-]{36})"', text)
    if m:
        out["user_id"] = m.group(1)
        if not out["principal_id"]:
            out["principal_id"] = m.group(1)
    m = re.search(
        r'approveUrl\\?":\\?"(https:[^"\\]+device/approve[^"\\]*)"',
        text,
    )
    if m and not out.get("approve_url"):
        out["approve_url"] = m.group(1).replace("\\/", "/")
    m = re.search(r'"approveUrl":"(https:[^"]+device/approve[^"]*)"', text)
    if m:
        out["approve_url"] = m.group(1)
    return out


def _request_device_code(timeout: int = 20) -> dict | None:
    """申请 device_code；优先 curl_cffi（与 session 同栈），失败再回落 urllib。"""
    data = {
        "client_id": GROK_CLI_CLIENT_ID,
        "scope": OIDC_SCOPES,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
    }
    try:
        r = requests.post(
            f"{OIDC_ISSUER}/oauth2/device/code",
            data=data,
            headers=headers,
            impersonate=DEFAULT_IMPERSONATE,
            timeout=timeout,
            **_proxy_kw(),
        )
        if r.status_code == 429 or "rate" in (r.text or "").lower():
            return {
                "_error": f"device/code rate_limited HTTP {r.status_code}: {(r.text or '')[:200]}"
            }
        if r.status_code >= 400:
            return {
                "_error": f"device/code HTTP {r.status_code}: {(r.text or '')[:200]}"
            }
        return r.json()
    except Exception:
        pass
    # 回落 urllib
    try:
        req = urllib.request.Request(
            f"{OIDC_ISSUER}/oauth2/device/code",
            data=urllib.parse.urlencode(data).encode(),
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")[:200]
        except Exception:
            pass
        if e.code == 429 or "rate" in body.lower():
            return {"_error": f"device/code rate_limited HTTP {e.code}: {body}"}
        return {"_error": f"device/code HTTP {e.code}: {body}"}
    except Exception as e:
        return {"_error": f"device/code 异常: {e}"}


def _poll_device_token(
    device_code: str,
    interval: int,
    expires_in: int,
    timeout: int = 60,
) -> dict | None:
    """
    approve 之后立刻查 token，不再先傻等一个 interval。
    仍遵守 slow_down / authorization_pending，保证成功率。

    成功返回 token dict；失败返回 None 或 {"_error": "..."}。
    """
    deadline = time.time() + min(int(expires_in or 1800), timeout)
    # 服务端 interval 常为 5；我们用更短的本地间隔，被 slow_down 再拉长
    server_interval = max(1, int(interval or 5))
    wait = min(1.2, float(server_interval))
    net_fail = 0
    first = True
    last_err = "token poll timeout"
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": GROK_CLI_CLIENT_ID,
        "device_code": device_code,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    while time.time() < deadline:
        if not first:
            time.sleep(wait)
        first = False
        try:
            r = requests.post(
                f"{OIDC_ISSUER}/oauth2/token",
                data=form,
                headers=headers,
                impersonate=DEFAULT_IMPERSONATE,
                timeout=20,
                **_proxy_kw(),
            )
            body_text = r.text or ""
            try:
                body = r.json() if body_text else {}
            except Exception:
                body = {}
            if r.status_code < 400 and (body.get("access_token") or body.get("key")):
                return body
            error = (body.get("error") if isinstance(body, dict) else "") or ""
            if error == "authorization_pending":
                net_fail = 0
                wait = min(max(wait, float(server_interval) * 0.6), 6.0)
                last_err = "authorization_pending"
                continue
            if error == "slow_down":
                wait = min(wait + 3.0, 15.0)
                last_err = "slow_down"
                continue
            if error:
                desc = body.get("error_description") or ""
                last_err = f"{error}" + (f": {desc}" if desc else "")
                # invalid_grant / access_denied / expired_token：别空转
                return {"_error": last_err}
            net_fail += 1
            last_err = f"token HTTP {r.status_code}: {body_text[:160]}"
            if net_fail >= 5:
                return {"_error": last_err}
            wait = min(wait + 1.5, 12.0)
            continue
        except Exception as e:
            # 瞬时网络：多试几次，别一次超时就放弃已 approve 的 flow
            net_fail += 1
            last_err = f"token poll 异常: {e}"
            if net_fail >= 6:
                return {"_error": last_err}
            wait = min(wait + 1.0, 10.0)
            continue
    return {"_error": last_err}


def _rfc3339_ns(ts: float) -> str:
    """与 grokcli-2api 一致的 expires_at 格式。"""
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond * 1000):09d}Z"


def token_to_auth_entry(token: dict, email: str = "") -> dict[str, Any]:
    """
    将 device flow 得到的 token 转成上游 /accounts/import 可接受的 entry。
    与 grokcli-2api sso_to_auth_json.token_to_auth_entry 字段对齐。
    """
    access = (token or {}).get("access_token") or (token or {}).get("key") or ""
    refresh = (token or {}).get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int((token or {}).get("expires_in") or 21600)
    if "exp" in payload:
        expires_at = _rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = _rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = _rfc3339_ns(float(iat) if iat else time.time())

    return {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or payload.get("email") or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": GROK_CLI_CLIENT_ID,
    }


# ------------------------------------------------------------------ #
# token 落盘：keys/token.txt（一行一个 JSON，test_grok45.py 可直接读）
# 目的：把 device flow 换到的 access_token / refresh_token 持久化，
#       进程重启后不必再用 sso 重换；也是「注册成功但 enrich 没跑完」的兜底。
# ------------------------------------------------------------------ #
_TOKEN_FILE_LOCK = threading.Lock()
_TOKEN_FILE_SEEN: dict[str, set[str]] = {}


def token_file_path() -> Path:
    """token 落盘路径：GROK_TOKEN_FILE 覆盖（相对路径按仓库根算），默认 keys/token.txt。"""
    raw = (os.environ.get("GROK_TOKEN_FILE") or "").strip()
    if not raw:
        return _BASE_DIR / "keys" / "token.txt"
    p = Path(raw)
    return p if p.is_absolute() else (_BASE_DIR / p)


def _token_record_key(rec: dict) -> str:
    return f"{rec.get('email') or ''}|{rec.get('access_token') or ''}"


def _token_seen_for(path: Path) -> set[str]:
    """进程内缓存已落盘的 (email, at) 集合，首次调用时扫一遍文件。"""
    key = str(path)
    seen = _TOKEN_FILE_SEEN.get(key)
    if seen is not None:
        return seen
    seen = set()
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(rec, dict):
                        seen.add(_token_record_key(rec))
    except Exception:
        pass
    _TOKEN_FILE_SEEN[key] = seen
    return seen


def build_token_record(
    email: str,
    token: dict,
    *,
    sso: str = "",
    note: str = "",
) -> dict:
    """把 device flow 原始 token 整理成落盘记录（保留 rt / id_token）。"""
    t = token or {}
    access = str(t.get("access_token") or t.get("key") or "")
    payload = decode_jwt_payload(access) if access else {}
    expires_at = ""
    if payload.get("exp"):
        try:
            expires_at = _rfc3339_ns(float(payload["exp"]))
        except Exception:
            expires_at = ""
    if not expires_at:
        try:
            expires_at = _rfc3339_ns(time.time() + float(t.get("expires_in") or 21600))
        except Exception:
            expires_at = ""
    rec = {
        "email": email or str(t.get("email") or "") or str(payload.get("email") or ""),
        "access_token": access,
        "refresh_token": str(t.get("refresh_token") or ""),
        "id_token": str(t.get("id_token") or ""),
        "token_type": str(t.get("token_type") or "Bearer"),
        "scope": str(t.get("scope") or ""),
        "expires_at": expires_at,
        "user_id": str(payload.get("sub") or payload.get("principal_id") or ""),
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": GROK_CLI_CLIENT_ID,
        "sso": sso or "",
        "saved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    if note:
        rec["note"] = note
    return rec


def append_token_record(
    email: str,
    token: dict,
    *,
    sso: str = "",
    note: str = "",
) -> str:
    """
    追加一行 token JSON；同一 (email, access_token) 只写一次。
    返回写入路径（去重命中时也返回路径），失败返回空串。绝不抛异常。
    """
    try:
        if not isinstance(token, dict):
            return ""
        rec = build_token_record(email, token, sso=sso, note=note)
        if not rec.get("access_token"):
            return ""
        path = token_file_path()
        with _TOKEN_FILE_LOCK:
            seen = _token_seen_for(path)
            k = _token_record_key(rec)
            if k in seen:
                return str(path)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                seen.add(k)
            except Exception:
                return ""
        return str(path)
    except Exception:
        return ""


def load_token_records() -> list[dict]:
    """读回 keys/token.txt（一行一个 JSON），损坏行自动跳过。"""
    out: list[dict] = []
    path = token_file_path()
    try:
        if not path.exists():
            return out
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if isinstance(rec, dict) and rec.get("access_token"):
                    out.append(rec)
    except Exception:
        return out
    return out


def sso_device_flow_to_token(
    sso: str,
    *,
    impersonate: str | None = None,
    timeout: int = 28,
    issue_token: bool | None = None,
) -> dict[str, Any]:
    """
    与 grokcli-2api sso_to_auth_json.sso_to_token 同路径：
    SSO cookie → 登录态探测 → OIDC device verify/approve → access_token。

    issue_token:
      - None: 跟全局 DEVICE_FLOW_ISSUE_TOKEN（默认 True，换到 access_token）
      - True: 批准后轮询 token（生产路径）
      - False: 批准成功即返回（仅诊断用）

    加固：
    - 同意页字段/approve URL 从当前 HTML 自动解析（跟随页面版本）
    - 全局冷却（rate_limited 后拉长间隔）
    - TLS/超时失败时轮换 impersonate
    """
    s = (sso or "").strip()
    if not s:
        return {"ok": False, "error": "空 sso", "token": None, "payload": {}}
    if not is_sso_jwt_shape(s):
        return {"ok": False, "error": "非有效 JWT 形态", "token": None, "payload": {}}

    do_token = DEVICE_FLOW_ISSUE_TOKEN if issue_token is None else bool(issue_token)
    payload = decode_jwt_payload(s)
    proxy_kw = _proxy_kw()

    # 指纹列表：调用方指定的优先，再轮换稳妥指纹
    fps: list[str] = []
    if impersonate:
        fps.append(impersonate)
    for x in DEVICE_FLOW_IMPERSONATES:
        if x not in fps:
            fps.append(x)
    # 最多试 3 个指纹，避免一次导入拖太久
    fps = fps[:3]

    # 有限并发 + 全局冷却：限流时大家一起让路，不把成功率打穿
    with _DEVICE_FLOW_SEM:
        _wait_device_flow_cooldown()
        last_err = "device flow 失败"

        for fp_idx, fp in enumerate(fps):
            try:
                sess = requests.Session(impersonate=fp)
                # 浏览器同源 cookie：.x.ai 即可覆盖 accounts / auth
                sess.cookies.set("sso", s, domain=".x.ai", path="/")

                r = sess.get(
                    "https://accounts.x.ai/",
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                final_url = (r.url or "").lower()
                if "error=rate_limited" in final_url or "rate_limited" in final_url:
                    last_err = f"探测 rate_limited: {r.url}"
                    _mark_device_flow_cooldown(25 + 10 * fp_idx)
                    # 限流：立刻让路，别继续换指纹连打
                    break
                if "sign-in" in final_url or "sign-up" in final_url:
                    return {
                        "ok": False,
                        "error": f"会话无效（跳转 {r.url}）",
                        "token": None,
                        "payload": payload,
                    }
                if r.status_code >= 400:
                    last_err = f"探测 HTTP {r.status_code}"
                    continue
            except Exception as e:
                last_err = f"探测异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    # 换指纹再试
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            dc = _request_device_code(timeout=max(15, int(timeout)))
            if not dc or dc.get("_error"):
                last_err = (dc or {}).get("_error") or "device/code 申请失败"
                if _device_flow_error_kind(last_err) == "rate_limited":
                    _mark_device_flow_cooldown(30)
                # device/code 与指纹无关，不必换指纹空转
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }
            if not dc.get("device_code") or not dc.get("user_code"):
                last_err = "device/code 申请失败（无 device_code）"
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            user_code = str(dc["user_code"])
            verify_uri = (
                dc.get("verification_uri_complete")
                or f"{site_url}/oauth2/device?user_code={user_code}"
            )
            consent_html = ""
            consent_url = ""
            try:
                # 浏览器顺序：先打开 complete URI，再 POST verify
                sess.get(
                    verify_uri,
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                r = sess.post(
                    f"{OIDC_ISSUER}/oauth2/device/verify",
                    data={"user_code": user_code},
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": site_url,
                        "Referer": verify_uri,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                ru = r.url or ""
                consent_url = ru
                consent_html = r.text or ""
                if "rate_limited" in ru.lower() or "error=rate_limited" in ru.lower():
                    last_err = f"device verify 失败: {ru}"
                    _mark_device_flow_cooldown(30 + 10 * fp_idx)
                    time.sleep(1.5)
                    break
                if "consent" not in ru:
                    last_err = f"device verify 失败: {ru}"
                    # 非限流的 verify 失败（如 code 过期）换指纹意义不大，直接返回
                    if "error=" in ru.lower() and "rate_limited" not in ru.lower():
                        return {
                            "ok": False,
                            "error": last_err,
                            "token": None,
                            "payload": payload,
                        }
                    continue
            except Exception as e:
                last_err = f"device verify 异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            # 关键：同意页 form 字段 / approve URL 跟随当前页面版本，不写死
            page = _parse_device_consent_page(consent_html, consent_url)
            approve_url = page.get("approve_url") or f"{OIDC_ISSUER}/oauth2/device/approve"
            # 浏览器 SSR 表单 principal_id 为空；部分号带 userId 也能过——两种都试
            pid_candidates: list[str] = []
            page_pid = (page.get("principal_id") or page.get("user_id") or "").strip()
            # 先空（与页面 hidden 默认一致），再 userId
            pid_candidates.append("")
            if page_pid and page_pid not in pid_candidates:
                pid_candidates.append(page_pid)

            approve_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": site_url,
                "Referer": consent_url or verify_uri,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-User": "?1",
            }
            approved_ok = False
            try:
                for pid in pid_candidates:
                    approve_data = {
                        "user_code": page.get("user_code") or user_code,
                        "action": "allow",
                        "principal_type": page.get("principal_type") or "User",
                        "principal_id": pid,
                    }
                    r = sess.post(
                        approve_url,
                        data=approve_data,
                        headers=approve_headers,
                        timeout=timeout,
                        allow_redirects=True,
                        **proxy_kw,
                    )
                    ru = r.url or ""
                    body_low = (r.text or "").lower()
                    if "rate_limited" in ru.lower():
                        last_err = f"device approve 失败: {ru}"
                        _mark_device_flow_cooldown(30)
                        approved_ok = False
                        break
                    # deny 会落到 done?denied=1 —— 这是真拒绝，不是假成功
                    if "denied=1" in ru.lower():
                        last_err = f"device approve 被拒绝: {ru}"
                        return {
                            "ok": False,
                            "error": last_err,
                            "token": None,
                            "payload": payload,
                            "approved": False,
                        }
                    if "done" in ru or "authorized" in body_low:
                        approved_ok = True
                        # 有多个 pid 候选时，本轮只 approve 一次（code 已消耗）
                        break
                if not approved_ok and "rate_limited" not in str(last_err):
                    last_err = f"device approve 失败: {ru if 'ru' in locals() else 'no response'}"
                    return {
                        "ok": False,
                        "error": last_err,
                        "token": None,
                        "payload": payload,
                        "approved": False,
                    }
                if not approved_ok:
                    break
            except Exception as e:
                last_err = f"device approve 异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            # 诊断模式：只验证同意授权，不下发 token
            if not do_token:
                _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
                return {
                    "ok": True,
                    "error": None,
                    "token": None,
                    "payload": payload,
                    "has_refresh": False,
                    "impersonate": fp,
                    "approved": True,
                    "issue_token": False,
                    "approve_url": approve_url,
                    "user_code": user_code,
                    "note": "device approve 成功；已跳过 token 下发（GROK_DEVICE_FLOW_ISSUE_TOKEN=0）",
                }

            token = _poll_device_token(
                dc["device_code"],
                int(dc.get("interval") or 5),
                int(dc.get("expires_in") or 1800),
                timeout=45,
            )
            if isinstance(token, dict) and token.get("_error"):
                last_err = (
                    f"device approve 后 token 失败: {token.get('_error')}"
                )
                # invalid_grant：换指纹整条重来意义有限，但短歇后仍可再试一次会话
                time.sleep(1.0)
                continue
            if not token or not (token.get("access_token") or token.get("key")):
                # 假批准典型症状：页面已 done，但 token 仍 invalid_grant
                last_err = (
                    "device approve 后未拿到 access_token"
                    "（常见 invalid_grant/Access denied：会话无法真正授权）"
                )
                # approve 已成功但 token 轮询失败：短歇后换指纹整条重来
                time.sleep(1.0)
                continue

            # 成功后轻冷却，降低连打 rate_limited（比旧 2s 更省）
            _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
            return {
                "ok": True,
                "error": None,
                "token": token,
                "payload": payload,
                "has_refresh": bool(token.get("refresh_token")),
                "impersonate": fp,
                "approved": True,
                "issue_token": True,
            }

        if _device_flow_error_kind(last_err) == "rate_limited":
            _mark_device_flow_cooldown(20)
        return {
            "ok": False,
            "error": last_err,
            "token": None,
            "payload": payload,
        }


def validate_sso_cookie(
    sso: str,
    *,
    impersonate: str = DEFAULT_IMPERSONATE,
    user_agent: Optional[str] = None,
    timeout: int = 15,
    require_device_flow: bool = True,
    retries: int = 2,
    issue_token: bool | None = None,
) -> dict[str, Any]:
    """
    校验换到的 sso 是否真正可导入上游。

    默认 require_device_flow=True：走 OIDC device flow（与 import-sso 同路径）。
    issue_token 默认跟随 GROK_DEVICE_FLOW_ISSUE_TOKEN（默认 True，换到 access_token）。

    返回: {ok, error, payload, token?, approved?}
    """
    del user_agent  # 保留签名兼容
    s = (sso or "").strip()
    if not s:
        return {"ok": False, "error": "空 sso", "payload": {}}
    if not is_sso_jwt_shape(s):
        return {"ok": False, "error": "非有效 JWT 形态", "payload": {}}

    if not require_device_flow:
        # 浅校验（不推荐用于记成功）
        payload = decode_jwt_payload(s)
        try:
            sess = requests.Session(impersonate=impersonate or DEFAULT_IMPERSONATE)
            sess.cookies.set("sso", s, domain=".x.ai", path="/")
            r = sess.get(
                "https://accounts.x.ai/",
                timeout=timeout,
                allow_redirects=True,
                **_proxy_kw(),
            )
            final_url = (r.url or "").lower()
            if "sign-in" in final_url or "sign-up" in final_url:
                return {"ok": False, "error": f"会话无效（跳转 {r.url}）", "payload": payload}
            if r.status_code >= 400:
                return {"ok": False, "error": f"探测 HTTP {r.status_code}", "payload": payload}
            return {"ok": True, "error": None, "payload": payload}
        except Exception as e:
            return {"ok": False, "error": f"探测异常: {e}", "payload": payload}

    last_err = "device flow 失败"
    attempts = max(1, int(retries or 1))
    for i in range(1, attempts + 1):
        result = sso_device_flow_to_token(
            s,
            impersonate=None,  # 内部轮换稳妥指纹
            timeout=max(int(timeout or 20), 28),
            issue_token=issue_token,
        )
        if result.get("ok"):
            return result
        last_err = result.get("error") or last_err
        # 会话明确无效则不必重试
        if "会话无效" in str(last_err) or "非有效 JWT" in str(last_err):
            break
        if i < attempts:
            wait = _device_flow_wait_seconds(str(last_err), i)
            if _device_flow_error_kind(str(last_err)) == "rate_limited":
                _mark_device_flow_cooldown(wait)
            time.sleep(wait)
    return {
        "ok": False,
        "error": last_err,
        "payload": decode_jwt_payload(s),
        "token": None,
    }


def _protobuf_varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def encode_grpc_string_field(field_id: int, string_value: str) -> bytes:
    """protobuf length-delimited string field (wire type 2)."""
    value_bytes = string_value.encode("utf-8")
    key = (field_id << 3) | 2
    return bytes([key]) + _protobuf_varint(len(value_bytes)) + value_bytes


def encode_grpc_message(field_id, string_value):
    """兼容旧调用：单 string 字段 + grpc-web 帧。"""
    payload = encode_grpc_string_field(field_id, string_value)
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_create_email_validation_code(
    email: str, castle_request_token: Optional[str] = None
) -> bytes:
    """
    CreateEmailValidationCodeRequest:
      string email = 1;
      EmailTemplate email_template = 2;          # optional
      optional string castle_request_token = 3;
    """
    parts = [encode_grpc_string_field(1, email)]
    if castle_request_token is not None:
        parts.append(encode_grpc_string_field(3, castle_request_token))
    payload = b"".join(parts)
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_grpc_message_verify(email, code):
    p1 = encode_grpc_string_field(1, email)
    p2 = encode_grpc_string_field(2, code)
    payload = p1 + p2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


class LogBuffer:
    """线程安全日志缓冲，供控制台与 Web UI 共用。"""

    def __init__(self, maxlen: int = 2000):
        self._lock = threading.Lock()
        self._seq = 0
        self._entries = deque(maxlen=maxlen)

    def emit(self, message: str, level: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._seq += 1
            entry = {
                "id": self._seq,
                "time": ts,
                "level": level,
                "message": message,
            }
            self._entries.append(entry)
        print(f"[{ts}] {message}")
        return entry

    def latest_id(self) -> int:
        with self._lock:
            return int(self._seq)

    def since(self, after_id: int = 0, limit: int = 200):
        with self._lock:
            # 服务重启后 seq 从 0 起，浏览器仍可能带着旧 after_id → 永远空结果（日志“卡住”）
            if after_id > self._seq:
                items = list(self._entries)[-limit:]
            else:
                items = [e for e in self._entries if e["id"] > after_id]
                items = items[-limit:]
            return items

    def clear(self):
        with self._lock:
            self._entries.clear()


class RegisterEngine:
    """可被 CLI 与 Web UI 共用的注册引擎。"""

    def __init__(self, log_fn: Optional[Callable[[str, str], None]] = None):
        self.site_url = site_url
        self.config = {
            "site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
            "action_id": None,
            "state_tree": (
                "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22"
                "(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22"
                "__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2C"
                "null%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
            ),
        }
        self.post_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.stop_event = threading.Event()
        self._run_lock = threading.Lock()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._worker_thread: Optional[threading.Thread] = None
        # 注册 POST 起步节流（不包整次 HTTP，允许多线程并行飞）
        self._post_min_interval = 0.25
        self._last_post_start = 0.0
        # SSO 后的 device flow / 协议 / NSFW：后台跑，不堵下一号
        # enrich 线程可多开，真正卡点在 device flow 信号量（默认 2）
        self._enrich_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=6, thread_name_prefix="RegEnrich"
        )
        self._enrich_pending = 0
        self._enrich_lock = threading.Lock()

        self.success_count = 0
        self.fail_count = 0
        self.clean_count = 0
        self.marked_count = 0
        # 创邮尝试次数：数量 N = 创建 N 个邮箱就停（CLEAN/MARKED/失败都计 1 次）
        self.attempt_count = 0
        self._ss_attempt_lock = threading.Lock()
        # 连续 risk MARKED（跨线程）：触顶熔断 / 切代理 / 冷却
        self._ss_consecutive_deny = 0
        self._ss_deny_lock = threading.Lock()
        # 代理池轮换状态（跨 worker 共享）
        self._ss_proxy_pool: list[str] = []
        self._ss_proxy_idx = 0
        self._ss_proxy_switches = 0  # 本轮连续切代理次数
        self._ss_cooldown_until = 0.0
        self._ss_proxy_lock = threading.Lock()
        self.target_count = 0
        self.workers = 0
        self.start_time: Optional[float] = None
        # 任务结束后冻结耗时，避免 get_status 继续 now-start 空转计时
        self.end_time: Optional[float] = None
        self.output_file: Optional[str] = None
        self.credentials_file: Optional[str] = None
        self.status = "idle"  # idle | initializing | running | stopping | done | error
        self.error_message = ""
        # 默认同会话 CLEAN；可被 start(mode=) / GROK_REGISTER_MODE 覆盖
        self.register_mode = resolve_register_mode()
        self._ss_idx = 0
        self._ss_idx_lock = threading.Lock()
        # 足够覆盖大批量注册；过小会导致「成功 100、可导入只剩 50」
        self.recent_success: deque = deque(maxlen=5000)
        self._log_fn = log_fn or (lambda msg, level="info": print(msg))
        # Action ID 缓存：内存 + 磁盘，避免每次/重启都扫 JS（通常 5~20 秒）
        self._action_cache: dict = {
            "action_id": None,
            "site_key": None,
            "state_tree": None,
            "ts": 0.0,
        }
        # 页面发版后 server action id 会变；默认 30 分钟，可用 GROK_ACTION_CACHE_TTL 覆盖
        self._action_cache_ttl = max(60, int(_ACTION_CACHE_TTL))
        self._load_action_cache_disk()

    def log(self, message: str, level: str = "info"):
        self._log_fn(message, level)

    def _next_ss_idx(self) -> int:
        with self._ss_idx_lock:
            self._ss_idx += 1
            return self._ss_idx

    def _init_proxy_pool(self) -> None:
        """任务启动时装载代理池。"""
        pool = _ss_load_proxy_pool()
        with self._ss_proxy_lock:
            self._ss_proxy_pool = list(pool)
            self._ss_proxy_idx = 0
            self._ss_proxy_switches = 0
            self._ss_cooldown_until = 0.0
        if pool:
            self.log(
                f"代理池 {len(pool)} 条 · 当前 {_ss_mask_proxy(pool[0])}"
                f" · 切代理上限={_ss_proxy_switch_limit() or 'off'}"
                f" · 冷却={_ss_cooldown_sec():.0f}s",
                "info",
            )
        else:
            self.log("代理池空 · 直连", "info")

    def _current_proxy_spec(self) -> str:
        """当前生效代理（空=直连）。"""
        with self._ss_proxy_lock:
            pool = list(self._ss_proxy_pool or [])
            idx = int(self._ss_proxy_idx or 0)
        if not pool:
            return ""
        return pool[idx % len(pool)]

    def _wait_proxy_cooldown(self) -> bool:
        """
        若处于冷却窗口则阻塞等待（全局，所有 worker 同步）。
        返回 True = 被 stop_event 打断应退出；False = 可继续。
        多线程：只有「清零 until 的 leader」打结束日志，避免刷屏。
        """
        with self._ss_proxy_lock:
            until = float(self._ss_cooldown_until or 0.0)
        remain = until - time.time()
        if remain <= 0:
            return False
        # 进入冷却提示：每线程最多偶发，用 until 戳做简易去重
        log_key = f"cd:{int(until)}"
        if getattr(self, "_ss_cd_log_key", None) != log_key:
            self._ss_cd_log_key = log_key
            self.log(
                f"代理熔断冷却中 · 剩余 {remain:.0f}s · 到点继续",
                "warn",
            )
        # 分段睡，方便 stop；期间若其它线程已清 until，提前退出
        end = time.time() + remain
        while time.time() < end:
            if self.stop_event.is_set():
                return True
            with self._ss_proxy_lock:
                cur_until = float(self._ss_cooldown_until or 0.0)
            if cur_until <= 0 or cur_until < until - 0.01:
                # 已被 leader 清掉
                return False
            if self._sleep(min(1.0, max(0.05, end - time.time()))):
                return True
        with self._ss_proxy_lock:
            # 冷却结束：只复位计数，不额外再切一次
            # （进冷却时 _on_deny_rotate_proxy 已经切到下一条了）
            still_mine = abs(float(self._ss_cooldown_until or 0.0) - until) < 0.5
            if still_mine and float(self._ss_cooldown_until or 0.0) > 0:
                self._ss_cooldown_until = 0.0
                self._ss_proxy_switches = 0
                self._ss_consecutive_deny = 0
                leader = True
            else:
                leader = False
            pool = list(self._ss_proxy_pool or [])
            idx = int(self._ss_proxy_idx or 0)
            cur = pool[idx % len(pool)] if pool else ""
        if leader:
            self.log(
                f"冷却结束 · 继续 · 代理={_ss_mask_proxy(cur) if cur else '(direct)'}",
                "info",
            )
        return False

    def _on_deny_rotate_proxy(self) -> str:
        """
        deny/MARKED 熔断处理：
          - 有多代理：切换下一条；连续切换达上限 → 进冷却
          - 单代理/无池：按 deny_break 停批（由调用方读 consecutive_deny）
        返回动作标签：switched / cooldown / none / single
        """
        switch_limit = _ss_proxy_switch_limit()
        cool_sec = _ss_cooldown_sec()
        with self._ss_proxy_lock:
            pool = list(self._ss_proxy_pool or [])
            # 池≤1 或 切代理上限=0 → 不轮换，走单出口 deny_break 停批
            if len(pool) <= 1 or switch_limit <= 0:
                return "single"
            # 切下一条
            old_idx = int(self._ss_proxy_idx or 0)
            new_idx = (old_idx + 1) % len(pool)
            self._ss_proxy_idx = new_idx
            self._ss_proxy_switches = int(self._ss_proxy_switches or 0) + 1
            switches = self._ss_proxy_switches
            old_p = pool[old_idx]
            new_p = pool[new_idx]
            # 切代理后本代理 deny 计数清零，让新出口重新计
            self._ss_consecutive_deny = 0
            # 新出口指纹缓存失效，下一号强制复探
            try:
                _ss_invalidate_egress(new_p)
            except Exception:
                pass
            if switch_limit > 0 and switches >= switch_limit:
                self._ss_proxy_switches = 0
                if cool_sec > 0:
                    self._ss_cooldown_until = time.time() + float(cool_sec)
                    action = "cooldown"
                else:
                    # 冷却=0：视为立即继续，不写 until，避免浮点残差误进冷却窗
                    self._ss_cooldown_until = 0.0
                    action = "switched"
            else:
                action = "switched"
        if action == "cooldown":
            self.log(
                f"deny 熔断 · 已连续切代理 {switches} 次 · "
                f"进入冷却 {cool_sec:.0f}s"
                f"（{_ss_mask_proxy(old_p)} → {_ss_mask_proxy(new_p)}）",
                "warn",
            )
        else:
            self.log(
                f"deny 熔断 · 切代理"
                f"（{_ss_mask_proxy(old_p)} → {_ss_mask_proxy(new_p)}）"
                f" · 本轮切换 {switches}"
                + (f"/{switch_limit}" if switch_limit else ""),
                "warn",
            )
        return action

    def _freeze_elapsed(self) -> None:
        """任务结束时钉死 end_time，页面耗时不再往上爬。"""
        if self.start_time and self.end_time is None:
            self.end_time = time.time()

    def get_status(self) -> dict:
        elapsed = 0.0
        avg = 0.0
        if self.start_time:
            # 运行中：实时；已结束：用 end_time 冻结，禁止空转计时
            if self.status in ("initializing", "running", "stopping"):
                end = time.time()
            else:
                end = self.end_time if self.end_time is not None else self.start_time
                # 兼容旧进程：done 了但没 end_time，立刻钉死一次
                if self.end_time is None and self.status in ("done", "error", "idle"):
                    self.end_time = time.time()
                    end = self.end_time
            elapsed = max(0.0, float(end) - float(self.start_time))
            if self.success_count > 0:
                avg = elapsed / self.success_count
        progress = 0.0
        attempts = int(getattr(self, "attempt_count", 0) or 0)
        if self.target_count > 0:
            # 进度条 = CLEAN 成功 / 目标（创邮次数另字段 attempt_count，别拿来当完成度）
            # 否则数量=1 时一建邮就 100%，验码/signup 还在跑也显示满格
            progress = min(100.0, float(self.success_count) / self.target_count * 100)
        return {
            "status": self.status,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "clean_count": int(getattr(self, "clean_count", 0) or 0),
            "marked_count": int(getattr(self, "marked_count", 0) or 0),
            "attempt_count": attempts,
            "target_count": self.target_count,
            "workers": self.workers,
            "register_mode": getattr(self, "register_mode", None) or resolve_register_mode(),
            "elapsed": round(elapsed, 1),
            "avg_seconds": round(avg, 1),
            "progress": round(progress, 1),
            "output_file": self.output_file or "",
            "credentials_file": self.credentials_file or "",
            "action_id": self.config.get("action_id") or "",
            "site_key": self.config.get("site_key") or "",
            "error_message": self.error_message,
            "enrich_pending": int(getattr(self, "_enrich_pending", 0) or 0),
            "token_ready_count": sum(
                1
                for it in self.recent_success
                if is_auth_token_usable(it.get("auth_token"))
            ),
            # 不把完整 sso / token 暴露给前端轮询；导入走服务端 id 匹配
            "recent_success": [
                {
                    "id": it.get("id"),
                    "email": it.get("email"),
                    "sso_preview": it.get("sso_preview"),
                    "sso": it.get("sso") or "",  # 完整 SSO，供页面复制/测试
                    "has_token": is_auth_token_usable(it.get("auth_token")),
                    "nsfw": it.get("nsfw"),
                    "clean": it.get("clean"),
                    "time": it.get("time"),
                    "imported": bool(it.get("imported")),
                }
                for it in self.recent_success
            ],
            "running": self.status in ("initializing", "running", "stopping"),
            "proxy_pool_size": len(getattr(self, "_ss_proxy_pool", None) or []),
            "proxy_current": _ss_mask_proxy(self._current_proxy_spec())
            if hasattr(self, "_ss_proxy_pool")
            else "",
            "proxy_switches": int(getattr(self, "_ss_proxy_switches", 0) or 0),
            "consecutive_deny": int(getattr(self, "_ss_consecutive_deny", 0) or 0),
            "cooldown_remain": max(
                0.0,
                float(getattr(self, "_ss_cooldown_until", 0) or 0) - time.time(),
            ),
        }

    def is_running(self) -> bool:
        return self.status in ("initializing", "running", "stopping")

    def _load_action_cache_disk(self) -> None:
        """进程启动时从磁盘恢复 Action ID，避免重启后又扫 10+ 秒。"""
        try:
            if not _ACTION_CACHE_FILE.is_file():
                return
            data = json.loads(_ACTION_CACHE_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not data.get("action_id"):
                return
            ts = float(data.get("ts") or 0)
            if time.time() - ts > self._action_cache_ttl:
                return
            self._action_cache = {
                "action_id": data.get("action_id"),
                "site_key": data.get("site_key"),
                "state_tree": data.get("state_tree"),
                "ts": ts,
            }
        except Exception:
            pass

    def _apply_action_cache(self) -> bool:
        cache = self._action_cache
        if not cache.get("action_id"):
            # 内存空时再试一次磁盘（热更新/其他进程写过）
            self._load_action_cache_disk()
            cache = self._action_cache
        if not cache.get("action_id"):
            return False
        if time.time() - float(cache.get("ts") or 0) > self._action_cache_ttl:
            return False
        self.config["action_id"] = cache["action_id"]
        if cache.get("site_key"):
            self.config["site_key"] = cache["site_key"]
        if cache.get("state_tree"):
            self.config["state_tree"] = cache["state_tree"]
        return True

    def _save_action_cache(self) -> None:
        self._action_cache = {
            "action_id": self.config.get("action_id"),
            "site_key": self.config.get("site_key"),
            "state_tree": self.config.get("state_tree"),
            "ts": time.time(),
        }
        try:
            _ACTION_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _ACTION_CACHE_FILE.write_text(
                json.dumps(self._action_cache, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def initialize(self, force_rescan: bool = False) -> bool:
        self.status = "initializing"
        mode = resolve_register_mode(getattr(self, "register_mode", None))
        self.register_mode = mode
        # 同会话 CLEAN 路径不依赖 Next.js Server Action ID（页内 fetch 自取）
        if mode == "same_session":
            if not self.config.get("site_key"):
                self.config["site_key"] = "0x4AAAAAAAhr9JGVDZbrZOo0"
            # 尽量用缓存 action_id（不强制）；没有也不阻塞
            self._apply_action_cache()
            self.log(
                "路径=same_session（同页 castle mint + 页内 fetch · CLEAN 主路径）",
                "success",
            )
            self.log(
                f"代理={_ss_local_proxy_spec()} · Turnstile 并行预解 · camoufox",
                "info",
            )
            return True

        self.log(
            "路径=protocol（REST 发码/验码/注册 + 无头浏览器 mint Castle）",
            "info",
        )
        # 优先用缓存，启动几乎立刻进入注册
        if not force_rescan and self._apply_action_cache():
            aid = self.config["action_id"] or ""
            self.log(
                f"使用缓存 Action ID: {aid[:18]}…（TTL {self._action_cache_ttl // 60}m，"
                f"过期会自动跟页面版本）",
                "success",
            )
            return True

        self.log(
            "正在初始化：扫描 accounts.x.ai/sign-up 提取当前页面 Server Action ID…",
            "info",
        )
        t0 = time.time()
        start_url = f"{self.site_url}/sign-up"
        proxy_kw = _proxy_kw()
        with requests.Session(impersonate=DEFAULT_IMPERSONATE) as s:
            try:
                html = s.get(start_url, timeout=20, **proxy_kw).text
                key_match = re.search(r'sitekey":"(0x4[a-zA-Z0-9_-]+)"', html)
                if key_match:
                    self.config["site_key"] = key_match.group(1)
                # 优先 next-router-state-tree；部分构建写在 flight 里
                tree_match = re.search(
                    r'next-router-state-tree":"([^"]+)"', html
                ) or re.search(
                    r'"children":\["sign-up"', html
                )
                if tree_match and hasattr(tree_match, "group") and tree_match.lastindex:
                    self.config["state_tree"] = tree_match.group(1)
                soup = BeautifulSoup(html, "html.parser")
                js_urls = [
                    urljoin(start_url, script["src"])
                    for script in soup.find_all("script", src=True)
                    if "_next/static" in script.get("src", "")
                ]
                # 1) HTML 内联 flight 也可能带 id
                aid = _extract_signup_action_id(html)
                # 2) 扫 JS chunk：优先 createServerReference(..., "default")
                if not aid:
                    for js_url in js_urls:
                        try:
                            js_content = s.get(js_url, timeout=15, **proxy_kw).text
                        except Exception:
                            continue
                        aid = _extract_signup_action_id(js_content)
                        if aid:
                            break
                self.config["action_id"] = aid
                if aid:
                    cost = time.time() - t0
                    self.log(
                        f"Action ID: {aid}（扫描耗时 {cost:.1f}s，已跟随当前页面版本）",
                        "success",
                    )
            except Exception as e:
                self.error_message = f"初始化扫描失败: {e}"
                self.log(self.error_message, "error")
                self.status = "error"
                return False

        if not self.config["action_id"]:
            self.error_message = "未找到 Action ID（页面结构可能已变）"
            self.log(self.error_message, "error")
            self.status = "error"
            return False
        self._save_action_cache()
        return True

    def send_email_code_grpc(self, session, email, castle_request_token: Optional[str] = None):
        """协议发码。可选带 castle_request_token（field 3）。
        返回 (ok, 友好失败原因)；ok=True 时 reason 为空串。"""
        url = f"{self.site_url}/auth_mgmt.AuthManagement/CreateEmailValidationCode"
        data = encode_create_email_validation_code(email, castle_request_token)
        headers = {
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": "connect-es/2.1.1",
            "origin": self.site_url,
            "referer": f"{self.site_url}/sign-up?redirect=grok-com",
        }
        try:
            res = session.post(url, data=data, headers=headers, timeout=15)
            if res.status_code != 200:
                return False, f"HTTP {res.status_code}（页面/服务异常）"
            gs = res.headers.get("grpc-status") or res.headers.get("Grpc-Status")
            gm = res.headers.get("grpc-message") or res.headers.get("Grpc-Message")
            if gm:
                try:
                    gm = urllib.parse.unquote(gm)
                except Exception:
                    pass
            if gs is not None and str(gs) not in ("0", ""):
                return False, self._friendly_grpc_error(gs, gm)
            body = res.content or b""
            if b"grpc-status:" in body and b"grpc-status:0" not in body:
                # trailer 非 0
                if b"grpc-status:0\r\n" not in body and b"grpc-status:0\n" not in body:
                    # 可能只有非 0 status
                    if b"grpc-status:" in body:
                        # 粗判：出现 status 且不是 0
                        text = body.decode("latin1", errors="replace")
                        if "grpc-status:0" not in text:
                            trailer_gs = re.search(r"grpc-status:\s*(\d+)", text)
                            trailer_gm = re.search(r"grpc-message:\s*(.+)", text)
                            return False, self._friendly_grpc_error(
                                trailer_gs.group(1) if trailer_gs else "",
                                (trailer_gm.group(1).strip() if trailer_gm else ""),
                            )
            return True, ""
        except Exception as e:
            self.log(f"{email} 发送验证码异常: {e}", "error")
            return False, f"网络/请求异常: {e}"

    def _friendly_grpc_error(self, gs: str, gm: str = "") -> str:
        """把 grpc-status / grpc-message 转成面向用户的友好提示。"""
        low = (gm or "").lower()
        if gs in ("8", "14") and ("rate" in low or "too many" in low or "validation codes" in low):
            return "发码被限流：x.ai 认为该邮箱发码过于频繁，请更换邮箱或稍等片刻再试"
        if gs in ("8", "14"):
            return "服务繁忙或已被限流（grpc-status=8），建议更换邮箱稍后再试"
        if gs in ("3",):
            return "邮箱格式可能不受支持，请更换有效邮箱"
        if gs in ("5",):
            return "邮箱不存在或不可用（5 NOT_FOUND），请更换邮箱"
        if gs in ("16",):
            return "未认证：会话无效，建议重启任务"
        if gm:
            return f"服务端拒绝：{gm}"
        return f"服务端拒绝（grpc-status={gs or '未知'}）"

    def verify_email_code_grpc(self, session, email, code):
        url = f"{self.site_url}/auth_mgmt.AuthManagement/VerifyEmailValidationCode"
        data = encode_grpc_message_verify(email, code)
        headers = {
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": "connect-es/2.1.1",
            "origin": self.site_url,
            "referer": f"{self.site_url}/sign-up?redirect=grok-com",
        }
        try:
            res = session.post(url, data=data, headers=headers, timeout=15)
            return res.status_code == 200
        except Exception as e:
            self.log(f"{email} 验证验证码异常: {e}", "error")
            return False

    # ---------- 新 REST 认证接口（2026-10 起，发码/验码）----------
    def _auth_api_headers(self, user_agent: Optional[str] = None) -> dict:
        headers = {
            "content-type": "application/json",
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "origin": self.site_url,
            "referer": f"{self.site_url}/sign-up",
        }
        if user_agent:
            headers["user-agent"] = user_agent
        return headers

    @staticmethod
    def _apply_browser_session(session, cookies: Optional[dict]) -> int:
        """把浏览器 cookie 灌进 curl_cffi 会话：新发码接口要求与 Castle mint 同会话。"""
        n = 0
        for name, value in (cookies or {}).items():
            if not name or value is None:
                continue
            try:
                session.cookies.set(str(name), str(value), domain="accounts.x.ai")
                n += 1
            except Exception:
                continue
        return n

    def _friendly_api_error(self, code: str, raw: str = "") -> str:
        """把新 REST 接口的 error code 转成面向用户的提示。"""
        c = (code or "").strip().lower()
        if "email-signup-unavailable" in c:
            return (
                "服务端判定当前出口/会话不能邮箱注册"
                "（account:email-signup-unavailable），请更换代理出口后重试"
            )
        if "disposable" in c or "domain-rejected" in c or "domain-pending" in c:
            return "该邮箱域名被 x.ai 拒绝（一次性邮箱 / 域名未验证），请更换邮箱域名"
        if "rate" in c:
            return "发码被限流（同一邮箱或出口请求过于频繁），稍后或换邮箱重试"
        if "castle" in c:
            return "浏览器校验（Castle）未通过，请重试"
        if "malformed" in c or "invalid-email" in c:
            return "邮箱格式不被接受"
        if "in-use" in c or "existing-email" in c:
            return "该邮箱已注册，请更换邮箱"
        return raw or (f"服务端拒绝：{code}" if code else "服务端拒绝（未知原因）")

    def send_email_code_api(
        self,
        session,
        email,
        castle_request_token: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """新 JSON 发码接口。

        返回 (ok, reason)；返回 None 表示接口不存在（旧部署），调用方应回退 grpc。
        """
        url = f"{self.site_url}{AUTH_CODE_SEND_PATH}"
        payload: dict = {"email": email}
        if castle_request_token:
            payload["castleRequestToken"] = castle_request_token
        try:
            res = session.post(
                url,
                json=payload,
                headers=self._auth_api_headers(user_agent),
                timeout=20,
            )
        except Exception as e:
            return False, f"网络/请求异常: {e}"
        if res.status_code in (404, 405):
            return None
        data: dict = {}
        try:
            data = res.json() or {}
        except Exception:
            data = {}
        if res.status_code == 200:
            if data.get("ok") or not data:
                return True, ""
            code = str(data.get("code") or "")
            if not code:
                return True, ""
            return False, self._friendly_api_error(code, str(data.get("error") or ""))
        code = str(data.get("code") or "")
        return False, self._friendly_api_error(
            code, str(data.get("error") or (res.text or "")[:160])
        )

    def verify_email_code_api(
        self,
        session,
        email,
        code: str,
        user_agent: Optional[str] = None,
    ):
        """新 JSON 验码接口；返回 None 表示接口不存在，应回退 grpc。"""
        url = f"{self.site_url}{AUTH_CODE_VERIFY_PATH}"
        headers = self._auth_api_headers(user_agent)
        try:
            res = session.post(
                url, json={"email": email, "code": code}, headers=headers, timeout=20
            )
        except Exception as e:
            return False, f"网络/请求异常: {e}"
        if res.status_code in (404, 405):
            return None
        data: dict = {}
        try:
            data = res.json() or {}
        except Exception:
            data = {}
        if res.status_code == 200 and (data.get("ok") or not data):
            return True, ""
        code_name = str(data.get("code") or "")
        low = code_name.lower()
        if "invalid" in low or "expired" in low:
            return False, "验证码无效或已过期"
        return False, self._friendly_api_error(code_name, str(data.get("error") or ""))

    @staticmethod
    def _browser_proxy() -> Optional[dict]:
        """注册代理 → Playwright proxy dict（浏览器必须与 curl 同出口）。"""
        try:
            proxies = _configured_curl_proxies()
            spec = str(proxies.get("https") or proxies.get("http") or "").strip()
        except Exception:
            spec = ""
        if not spec:
            return None
        try:
            pw_proxy = parse_proxy_spec(spec)
        except Exception:
            pw_proxy = None
        return pw_proxy or {"server": spec}

    def _mint_send_code_castle(self):
        """发码前：无头浏览器 mint Castle，并带回同会话 cookie / UA。

        返回 (castle_token, cookies, user_agent)；失败时 token 为 None。
        """
        if not send_code_castle_enabled():
            return None, {}, ""
        try:
            from g.castle_service import mint_castle_from_browser
        except Exception as e:  # pragma: no cover
            self.log(f"Castle 模块不可用: {e}", "warn")
            return None, {}, ""
        pw_proxy = self._browser_proxy()
        t0 = time.time()
        try:
            r = mint_castle_from_browser(proxy=pw_proxy, user_agent=_DEFAULT_BROWSER_UA)
        except Exception as e:
            self.log(f"Castle mint 异常: {e}", "warn")
            return None, {}, ""
        cost = time.time() - t0
        tok = (r or {}).get("castle") or None
        cookies = dict((r or {}).get("cookies") or {})
        ua = str((r or {}).get("user_agent") or _DEFAULT_BROWSER_UA)
        if tok:
            self.log(
                f"Castle OK len={len(tok)} · cookie {len(cookies)} 条 · {cost:.1f}s",
                "info",
            )
        else:
            self.log(
                f"Castle mint 失败：{(r or {}).get('error') or 'unknown'}（{cost:.1f}s）",
                "warn",
            )
        return tok, cookies, ua

    def signup_create_account_api(
        self,
        session,
        *,
        email: str,
        password: str,
        email_validation_code: str,
        turnstile_token: str,
        castle_request_token: Optional[str] = None,
        given_name: str = "",
        family_name: str = "",
        marketing_opt_in: bool = False,
        user_agent: Optional[str] = None,
    ):
        """新 JSON 注册端点 /api/auth/sign-up/create-account（2026-10 起）。

        返回 (ok, reason, data)；返回 None 表示端点不存在（旧部署），应回退 RSC。
        """
        url = f"{self.site_url}/api/auth/sign-up/create-account"
        payload = {
            "email": email,
            "password": password,
            "givenName": given_name or generate_random_name(),
            "familyName": family_name or generate_random_name(),
            "emailValidationCode": re.sub(r"\D", "", str(email_validation_code or "")),
            "turnstileToken": turnstile_token,
            "marketingEmailOptIn": bool(marketing_opt_in),
        }
        if castle_request_token:
            payload["castleRequestToken"] = castle_request_token
        try:
            res = session.post(
                url,
                json=payload,
                headers=self._auth_api_headers(user_agent),
                timeout=30,
            )
        except Exception as e:
            return False, f"网络/请求异常: {e}", {}
        if res.status_code in (404, 405):
            return None
        data: dict = {}
        try:
            data = res.json() or {}
        except Exception:
            data = {}
        if res.status_code == 200 and not data.get("error"):
            return True, "", data
        code = str(data.get("code") or "")
        low = code.lower()
        if "existing" in low:
            return False, "该邮箱已注册（account:existing-email）", data
        if "castle" in low:
            return False, "Castle 校验失败（token 过期或与当前会话不匹配）", data
        if "validation-code" in low or "invalid-validation" in low:
            return False, "邮箱验证码无效或已过期", data
        if "turnstile" in low:
            return False, "Turnstile 校验失败，请重试", data
        if "password" in low:
            return False, "密码不符合要求", data
        return (
            False,
            self._friendly_api_error(code, str(data.get("error") or (res.text or "")[:160])),
            data,
        )

    def _sleep(self, seconds: float) -> bool:
        """可中断 sleep。返回 True 表示已被 stop。"""
        if seconds <= 0:
            return self.stop_event.is_set()
        return self.stop_event.wait(timeout=seconds)

    def _fail_account(
        self,
        email_service: Optional[EmailService],
        email: Optional[str],
        reason: str,
        level: str = "error",
        *,
        count_fail: bool = True,
    ) -> None:
        """
        单个账号失败：记失败、删邮箱、本账号结束。
        不置 stop_event，其它线程与后续账号继续跑到达目标。
        （同一邮箱不再换号死磕；新一轮会开新邮箱，属于新账号。）

        count_fail=False：仅收尾（如 MARKED 已记 marked_count），避免和「失败尝试」重复加。
        """
        if count_fail:
            self.fail_count += 1
        self.error_message = reason
        self.log(f"{reason} — 本账号结束，任务继续", level)
        if email and email_service is not None:
            try:
                email_service.delete_email(email)
            except Exception:
                pass

    def _emergency_save_sso(self, email: str, sso: str, reason: str = "") -> bool:
        """
        紧急落盘：任何已拿到的 SSO 都必须写文件，避免账号创建成功却因后续步骤丢号。
        不计入 success_count 上限拦截——宁可多写一行，也不能吞掉已建账号。
        返回 True 表示至少写入成功一处。
        """
        s = (sso or "").strip()
        if not s:
            return False
        ok = False
        try:
            emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
            emergency.parent.mkdir(parents=True, exist_ok=True)
            with self.file_lock:
                with open(emergency, "a", encoding="utf-8") as f:
                    f.write(f"{email}----{s}\n" if email else f"{s}\n")
                    ok = True
                if self.output_file:
                    with open(self.output_file, "a", encoding="utf-8") as f:
                        f.write(s + "\n")
                        ok = True
            self.log(
                f"{email} SSO 已紧急落盘（{reason or '防丢号'}）→ keys/emergency_sso.txt + 任务文件",
                "success",
            )
        except Exception as e:
            self.log(f"{email} 紧急落盘失败: {e} | SSO 前缀 {s[:20]}…", "error")
        return ok

    def _save_credentials(self, email: str, password: str) -> str:
        """Persist login credentials separately from SSO-only import files."""
        if not email or not password:
            return ""
        raw_path = self.credentials_file
        if not raw_path:
            if self.output_file:
                output_path = Path(self.output_file)
                raw_path = str(
                    output_path.with_name(output_path.stem + "_credentials.csv")
                )
            else:
                raw_path = str(_BASE_DIR / "keys" / "credentials.csv")
            self.credentials_file = raw_path
        path = Path(raw_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            write_header = not path.exists() or path.stat().st_size == 0
            with open(path, "a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow(("email", "password"))
                writer.writerow((email, password))
            return str(path)
        except Exception as exc:
            self.log(f"{email} 登录凭据写入失败: {exc}", "error")
            return ""

    def _record_success(
        self,
        email: str,
        sso: str,
        unhinged_ok: bool,
        email_service: Optional[EmailService] = None,
        note: str = "",
        *,
        password: str = "",
        already_written: bool = False,
        auth_token: Optional[dict] = None,
    ) -> str:
        """
        写入 SSO、登录凭据并计入成功。返回 success_id（空串表示未计入成功列表）。
        same_session：停批看创邮次数，CLEAN 数可超过 target（在飞号收尾仍计成功）。
        protocol：仍按 CLEAN 数顶 target。
        already_written=True：SSO 已在紧急落盘写过，只更新计数/UI，避免重复行。
        auth_token：注册时 device flow 换到的 token，导入上游可直写，免二次换票。
        """
        with self.file_lock:
            credentials_path = self._save_credentials(email, password)
            mode_now = resolve_register_mode(getattr(self, "register_mode", None))
            # same_session 以创邮次数停批；在飞号拿到 CLEAN 仍应进成功列表
            # protocol 旧路径才用 success_count 顶 target
            if (
                mode_now != "same_session"
                and self.success_count >= self.target_count
            ):
                if not self.stop_event.is_set():
                    self.stop_event.set()
                # 已达目标但仍拿到 SSO：紧急保存，绝不丢号
                if not already_written:
                    try:
                        emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
                        with open(emergency, "a", encoding="utf-8") as f:
                            f.write(f"{email}----{sso}\n")
                        self.log(f"{email} 已达目标，SSO 写入 emergency_sso.txt", "warn")
                    except Exception:
                        pass
                if email_service is not None:
                    try:
                        email_service.delete_email(email)
                    except Exception:
                        pass
                return ""
            if not already_written:
                try:
                    with open(self.output_file, "a", encoding="utf-8") as f:
                        f.write(sso + "\n")
                except Exception as write_err:
                    self.log(f"{email} 写入文件失败: {write_err}，尝试紧急落盘", "error")
                    try:
                        emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
                        with open(emergency, "a", encoding="utf-8") as f:
                            f.write(f"{email}----{sso}\n")
                    except Exception as e2:
                        self.log(f"{email} 紧急落盘也失败: {e2}", "error")
                        self.fail_count += 1
                        return ""

            self.success_count += 1
            avg = (time.time() - self.start_time) / max(1, self.success_count)
            nsfw_tag = "✓" if unhinged_ok else "…"
            # 浅拷贝 token，避免后续引用被外部改写
            cached_token = None
            if isinstance(auth_token, dict) and is_auth_token_usable(auth_token):
                cached_token = dict(auth_token)
                # 注册链路自己换到的票（protocol 模式）也落盘，别只留在内存
                tok_path = append_token_record(email, cached_token, sso=sso, note="register")
                if tok_path:
                    self.log(f"{email} token 已落盘（at+rt）: {tok_path}", "info")
            success_id = f"{int(time.time() * 1000)}_{self.success_count}"
            self.recent_success.appendleft(
                {
                    "id": success_id,
                    "email": email,
                    "sso": sso,
                    "sso_preview": (sso[:18] + "...") if len(sso) > 18 else sso,
                    "auth_token": cached_token,
                    "nsfw": unhinged_ok,
                    "clean": None,
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "imported": False,
                }
            )
            extra = f" | {note}" if note else ""
            attempts = int(getattr(self, "attempt_count", 0) or 0)
            self.log(
                f"CLEAN {self.success_count} · 创邮 {attempts}/{self.target_count} | {email} | "
                f"SSO: {sso[:15]}... | 平均: {avg:.1f}s | NSFW: {nsfw_tag}{extra}",
                "success",
            )
            if credentials_path:
                self.log(f"{email} 登录凭据已保存: {credentials_path}", "info")
            if email_service is not None:
                try:
                    email_service.delete_email(email)
                except Exception:
                    pass
            # same_session：停批看创邮次数，不在这里用 CLEAN 数提前停
            # protocol 旧路径仍可按 CLEAN 凑满（attempt 未启用时）
            if (
                resolve_register_mode(getattr(self, "register_mode", None)) != "same_session"
                and self.success_count >= self.target_count
                and not self.stop_event.is_set()
            ):
                self.stop_event.set()
                self.log(
                    f"已达到 CLEAN 目标: {self.success_count}/{self.target_count}，停止新注册",
                    "success",
                )
            return success_id

    def _update_success_meta(
        self,
        success_id: str,
        *,
        auth_token: Optional[dict] = None,
        unhinged_ok: Optional[bool] = None,
        clean: Optional[bool] = None,
        note: str = "",
    ) -> None:
        """后台 enrich 完成后回填 token / NSFW / risk 状态（按 id 匹配）。"""
        if not success_id:
            return
        with self.file_lock:
            for item in self.recent_success:
                if item.get("id") != success_id:
                    continue
                if isinstance(auth_token, dict) and is_auth_token_usable(auth_token):
                    item["auth_token"] = dict(auth_token)
                if unhinged_ok is not None:
                    item["nsfw"] = bool(unhinged_ok)
                if clean is not None:
                    item["clean"] = bool(clean)
                if note:
                    item["note"] = note
                break

    def _revoke_marked_success(
        self,
        success_id: str,
        *,
        email: str = "",
        summary: str = "",
    ) -> None:
        """
        MARKED 账号若已误入成功列表：踢出、回滚 success_count，禁止导入。
        主路径应在 risk 通过后再 _record_success；本方法仅兜底。
        """
        if not success_id:
            return
        removed = False
        with self.file_lock:
            keep: deque = deque(maxlen=self.recent_success.maxlen)
            for item in self.recent_success:
                if item.get("id") == success_id:
                    removed = True
                    continue
                keep.append(item)
            if removed:
                self.recent_success.clear()
                self.recent_success.extend(keep)
                if self.success_count > 0:
                    self.success_count -= 1
        if removed:
            self.log(
                f"{email or success_id} 已从成功列表移除（MARKED）"
                + (f" · {summary}" if summary else ""),
                "warn",
            )

    def _append_line(self, path: Path | str, line: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self.file_lock:
            with open(p, "a", encoding="utf-8") as f:
                f.write(line if line.endswith("\n") else line + "\n")

    def _probe_and_mark_clean(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str = "",
        success_id: str = "",
        proxy_spec: str = "",
        foreground: bool = True,
    ) -> Optional[bool]:
        """
        risk 探测：CLEAN 写 _clean.txt，MARKED 写 _marked.txt。
        默认前台串行（foreground=True）——和注册同线程整号跑完再开下一号。
        返回 True=CLEAN / False=MARKED / None=跳过或异常。
        """
        try:
            if AntibotService is None:
                self.log(f"{email} risk 跳过：AntibotService 不可用", "warn")
                return None
            # 探测走业务代理（与注册出口一致）
            if proxy_spec:
                url = ""
                try:
                    parsed = parse_proxy_spec(proxy_spec) or {}
                    url = (
                        parsed.get("server_url")
                        or parsed.get("server")
                        or ""
                    )
                except Exception:
                    url = ""
                if not url:
                    raw = (proxy_spec or "").strip()
                    if raw.startswith("http://") or raw.startswith("https://") or raw.startswith("socks"):
                        url = raw
                    elif raw:
                        url = f"http://{raw}"
                if url:
                    os.environ["GROK_PROXY"] = url
                    os.environ["XAI_PROXY"] = url
            self.log(f"{email} risk 探测开始…", "info")
            t0 = time.time()
            ab = AntibotService()
            # chrome124 经本地代理稳；chrome131 易 curl(35) OPENSSL invalid library
            # probe 内部：多 impersonate + 代理失败后直连兜底
            risk = ab.probe_account_risk(
                sso, sso_rw=sso_rw or sso, impersonate="chrome124", timeout=20
            )
            # 仍基建失败：强制直连再打一轮（绕开 7897 TLS 抖动）
            if AntibotService.is_risk_infra_error(risk):
                self.log(
                    f"{email} risk 基建抖动 · {AntibotService.risk_mark_summary(risk)[:80]} · 直连重试…",
                    "warn",
                )
                time.sleep(0.4)
                prev_force = os.environ.get("GROK_RISK_FORCE_DIRECT")
                try:
                    os.environ["GROK_RISK_FORCE_DIRECT"] = "1"
                    risk = ab.probe_account_risk(
                        sso,
                        sso_rw=sso_rw or sso,
                        impersonate="chrome124",
                        timeout=25,
                    )
                finally:
                    if prev_force is None:
                        os.environ.pop("GROK_RISK_FORCE_DIRECT", None)
                    else:
                        os.environ["GROK_RISK_FORCE_DIRECT"] = prev_force
            clean = bool(AntibotService.is_risk_clean(risk))
            summary = AntibotService.risk_mark_summary(risk)
            elapsed = round(time.time() - t0, 1)
            if clean:
                with self.file_lock:
                    self.clean_count += 1
                if self.output_file:
                    clean_path = Path(self.output_file).with_name(
                        Path(self.output_file).stem + "_clean.txt"
                    )
                    self._append_line(clean_path, f"{email}----{sso}")
                if success_id:
                    self._update_success_meta(
                        success_id, clean=True, note=f"risk=CLEAN {summary}"
                    )
                self.log(
                    f"{email} risk CLEAN · {summary} · {elapsed}s · "
                    f"CLEAN累计 {self.clean_count}",
                    "success",
                )
                return True
            # TLS/代理基建失败：SSO 可能仍是好号，禁止记 MARKED、不进 _marked
            if AntibotService.is_risk_infra_error(risk):
                if self.output_file:
                    infra_path = Path(self.output_file).with_name(
                        Path(self.output_file).stem + "_infra_retry.txt"
                    )
                    self._append_line(infra_path, f"{email}----{sso}")
                self.log(
                    f"{email} risk INFRA（TLS/代理探测失败，非业务 MARKED）· "
                    f"{summary} · {elapsed}s · SSO 已落 emergency，本号暂不进成功列表",
                    "warn",
                )
                # None = 探测失败（非 MARKED），调用方按失败尝试处理，不叠 marked_count
                return None
            # 真 MARKED（DENIED / false_clean / botFlag）：落盘，不进成功/导入
            with self.file_lock:
                self.marked_count += 1
            if self.output_file:
                marked = Path(self.output_file).with_name(
                    Path(self.output_file).stem + "_marked.txt"
                )
                self._append_line(marked, f"{email}----{sso}")
                meta = Path(self.output_file).with_name(
                    Path(self.output_file).stem + "_marked_meta.txt"
                )
                detail_bits = [
                    summary,
                    f"policy={risk.get('policy')}",
                    f"event={risk.get('event')}",
                    f"src={risk.get('bot_flag_source')}",
                    f"score={risk.get('risk_score')}",
                ]
                self._append_line(
                    meta, f"{email}\t" + " | ".join(str(x) for x in detail_bits if x)
                )
            if success_id:
                # 若历史上已进成功列表，踢掉并回滚成功计数
                self._revoke_marked_success(success_id, email=email, summary=summary)
            self.log(
                f"{email} risk MARKED · {summary} · {elapsed}s · "
                f"绕过成功列表/导入 · MARKED累计 {self.marked_count}",
                "warn",
            )
            return False
        except Exception as e:
            err_s = str(e)
            # 外层异常若是 curl TLS，同样不当 MARKED
            low = err_s.lower()
            if any(
                m in low
                for m in (
                    "curl: (35)",
                    "tls connect",
                    "openssl",
                    "invalid library",
                    "failed to perform",
                )
            ):
                self.log(
                    f"{email} risk 探测异常(INFRA): {err_s[:120]} · 非 MARKED",
                    "warn",
                )
                return None
            self.log(f"{email} risk 探测异常: {e}", "warn")
            return None
        finally:
            # 仅后台调度时扣 pending；前台不走 enrich 计数
            if not foreground:
                with self._enrich_lock:
                    self._enrich_pending = max(0, self._enrich_pending - 1)

    def _schedule_risk_probe(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str,
        success_id: str,
        proxy_spec: str = "",
    ) -> None:
        """兼容旧调用：后台 risk（same_session 已改前台，一般不再走这里）。"""
        with self._enrich_lock:
            self._enrich_pending += 1
        try:
            self._enrich_pool.submit(
                self._probe_and_mark_clean,
                email=email,
                sso=sso,
                sso_rw=sso_rw or "",
                success_id=success_id,
                proxy_spec=proxy_spec or "",
                foreground=False,
            )
        except Exception as e:
            with self._enrich_lock:
                self._enrich_pending = max(0, self._enrich_pending - 1)
            self.log(f"{email} 调度 risk 失败: {e}", "warn")

    def _throttle_signup_post(self) -> None:
        """注册 POST 起步节流：保证间隔，但不把整个 HTTP 锁死。"""
        with self.post_lock:
            now = time.time()
            wait = self._post_min_interval - (now - self._last_post_start)
            if wait > 0:
                time.sleep(wait)
            self._last_post_start = time.time()

    def _exchange_token_after_clean(
        self,
        *,
        email: str,
        sso: str,
        success_id: str = "",
        impersonate: str = "chrome131",
        user_agent: str = "",
        retries: int = 3,
        async_mode: bool = False,
    ) -> Optional[dict]:
        """
        换 token（device flow 发票）。
        默认由后台 enrich 池调用（async_mode=True），不堵注册主路径。
        成功则缓存到 recent_success，导入时优先直写；失败不改成功计数，
        导入侧仍可用 sso-to-oauth / 本机 device flow 兜底。
        """
        tag = "[后台] " if async_mode else ""
        self.log(f"{email} {tag}换 token 开始…", "info")
        t0 = time.time()
        try:
            check = validate_sso_cookie(
                sso,
                impersonate=impersonate or "chrome131",
                user_agent=user_agent or (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                require_device_flow=True,
                retries=max(1, int(retries or 3)),
                timeout=28,
                issue_token=True,
            )
            elapsed = round(time.time() - t0, 1)
            if check.get("ok") and isinstance(check.get("token"), dict):
                token = check.get("token")
                if is_auth_token_usable(token):
                    tok_path = append_token_record(email, token, sso=sso, note="enrich")
                    if tok_path:
                        self.log(f"{email} {tag}token 已落盘（at+rt）: {tok_path}", "info")
                    self._update_success_meta(
                        success_id,
                        auth_token=token,
                        note=f"token=cached · device_flow=ok · async={int(async_mode)} · {elapsed}s",
                    )
                    self.log(
                        f"{email} {tag}换 token 成功 · 已缓存 · {elapsed}s（导入可直写）",
                        "success",
                    )
                    return token
                self._update_success_meta(
                    success_id,
                    note=f"token=unusable · async={int(async_mode)} · {elapsed}s",
                )
                self.log(
                    f"{email} {tag}换 token 返回体不可用 · {elapsed}s（导入走兜底）",
                    "warn",
                )
                return None
            if check.get("ok") and check.get("approved") and not check.get("token"):
                self._update_success_meta(
                    success_id,
                    note=f"token=approved_no_body · async={int(async_mode)} · {elapsed}s",
                )
                self.log(
                    f"{email} {tag}换 token：approve 成功但无 token 体 · {elapsed}s（导入兜底）",
                    "warn",
                )
                return None
            err = check.get("error") or "device flow 失败"
            self._update_success_meta(
                success_id,
                note=f"token=fail · {str(err)[:60]} · async={int(async_mode)} · {elapsed}s",
            )
            self.log(
                f"{email} {tag}换 token 失败 · {err} · {elapsed}s（导入走 sso-to-oauth/兜底）",
                "warn",
            )
            return None
        except Exception as e:
            elapsed = round(time.time() - t0, 1)
            self.log(f"{email} {tag}换 token 异常 · {e} · {elapsed}s", "warn")
            self._update_success_meta(
                success_id,
                note=f"token=exc · {str(e)[:60]} · async={int(async_mode)}",
            )
            return None

    def _enrich_after_sso(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str,
        success_id: str,
        impersonate: str,
        user_agent: str,
        skip_token: bool = False,
        proxy_spec: str = "",
    ) -> None:
        """
        SSO 后后台收尾（enrich 池，不堵注册主路径）：
        - skip_token=False（same_session 默认）：先异步换 token，再协议/NSFW
        - skip_token=True：只做协议/NSFW（token 已在别处处理）
        失败不影响成功计数；导入侧可对缺 token 号走兜底。
        """
        try:
            # 协议 / NSFW 必须与注册同一条代理出口：
            # 直连往往连不上 grok.com，换出口又容易判异常 —— 这是
            # 「注册成功、最后 NSFW 这一步失败」的主因。
            enrich_proxies = _curl_proxies_from_spec(proxy_spec) or _configured_curl_proxies()
            user_agreement_service = UserAgreementService(proxies=enrich_proxies)
            nsfw_service = NsfwSettingsService(proxies=enrich_proxies)
            note_parts: list[str] = []
            auth_token = None

            if not skip_token:
                # 异步换 token：与下一号注册重叠
                auth_token = self._exchange_token_after_clean(
                    email=email,
                    sso=sso,
                    success_id=success_id,
                    impersonate=impersonate or "chrome131",
                    user_agent=user_agent or "",
                    async_mode=True,
                )
                if isinstance(auth_token, dict) and is_auth_token_usable(auth_token):
                    note_parts.append("token=async_cached")
                else:
                    note_parts.append("token=async_pending_or_fail")
            else:
                note_parts.append("token=skipped")

            unhinged_ok = False
            try:
                # 1) 同意 TOS（失败不再直接跳过 NSFW：REST 注册时 TOS 可能已接受）
                tos_ok = False
                tos_err = ""
                for _try in range(2):
                    tos_result = user_agreement_service.accept_tos_version(
                        sso=sso,
                        sso_rw=sso_rw or "",
                        impersonate=impersonate,
                        user_agent=user_agent,
                    )
                    if tos_result.get("ok"):
                        tos_ok = True
                        break
                    tos_err = str(tos_result.get("error") or tos_result)
                    if _try == 0:
                        time.sleep(0.5)
                if not tos_ok:
                    note_parts.append(f"协议失败: {tos_err}")
                    self.log(f"{email} [后台] 协议失败: {tos_err}", "warn")

                # 2) 开启 NSFW —— 成功与否只认 grpc-status，
                #    并读回 GetUserFeatureControls 做校验（失败也返回 HTTP 200，
                #    旧代码「HTTP 200 就算成功」会把没开成的号标成 ✓）。
                nsfw_ok = False
                nsfw_err = ""
                nsfw_detail = ""
                for _try in range(2):
                    nsfw_result = nsfw_service.enable_nsfw(
                        sso=sso,
                        sso_rw=sso_rw or "",
                        impersonate=impersonate,
                        user_agent=user_agent,
                        retries=0,
                    )
                    if nsfw_result.get("ok"):
                        nsfw_ok = True
                        nsfw_detail = (
                            "readback=ok"
                            if nsfw_result.get("readback_ok")
                            else "readback=n/a"
                        )
                        break
                    nsfw_err = str(nsfw_result.get("error") or nsfw_result)
                    if _try == 0:
                        time.sleep(0.5)

                if nsfw_ok:
                    note_parts.append(f"nsfw=ok({nsfw_detail})" if nsfw_detail else "nsfw=ok")
                    if not tos_ok:
                        note_parts.append("协议未确认")
                else:
                    note_parts.append(f"NSFW失败: {nsfw_err}")
                    self.log(f"{email} [后台] NSFW 失败: {nsfw_err}", "warn")
                unhinged_ok = nsfw_ok
            except Exception as post_err:
                note_parts.append(f"协议/NSFW异常: {post_err}")
                self.log(f"{email} [后台] 协议/NSFW 异常: {post_err}", "warn")

            note = "; ".join(str(x)[:100] for x in note_parts)
            # token 已在 _exchange_token_after_clean 里写过；这里再合并 note/nsfw
            self._update_success_meta(
                success_id,
                auth_token=auth_token if isinstance(auth_token, dict) else None,
                unhinged_ok=unhinged_ok,
                note=note,
            )
            if unhinged_ok:
                self.log(f"{email} [后台] NSFW 已开（grpc-status 0）", "success")
        except Exception as e:
            self.log(f"{email} [后台] enrich 异常: {e}", "warn")
        finally:
            with self._enrich_lock:
                self._enrich_pending = max(0, self._enrich_pending - 1)

    def _schedule_enrich(
        self,
        *,
        email: str,
        sso: str,
        sso_rw: str,
        success_id: str,
        impersonate: str,
        user_agent: str,
        skip_token: bool = False,
        proxy_spec: str = "",
    ) -> None:
        with self._enrich_lock:
            self._enrich_pending += 1
        try:
            self._enrich_pool.submit(
                self._enrich_after_sso,
                email=email,
                sso=sso,
                sso_rw=sso_rw or "",
                success_id=success_id,
                impersonate=impersonate,
                user_agent=user_agent,
                proxy_spec=proxy_spec,
                skip_token=skip_token,
            )
        except Exception as e:
            with self._enrich_lock:
                self._enrich_pending = max(0, self._enrich_pending - 1)
            self.log(f"{email} 调度后台 enrich 失败: {e}", "warn")

    def register_single_thread_same_session(self):
        """
        CLEAN 主路径：同页 fiber mint castle + 页内 fetch 发码/验码/signup。
        对齐 standalone_same_session_n；禁止拆会话 mint 再外层 curl。
        """
        if self.workers > 1:
            if self._sleep(random.uniform(0, min(1.2, 0.12 * self.workers))):
                return

        try:
            email_service = EmailService()
            turnstile_service = TurnstileService()
        except Exception as e:
            self.log(f"服务初始化失败: {e}", "error")
            self.stop_event.set()
            return

        site_key = self.config.get("site_key") or "0x4AAAAAAAhr9JGVDZbrZOo0"
        current_email = None
        # 数量 N = 创建 N 个邮箱就停（对齐 standalone COUNT）
        # 不再「凑满 N 个 CLEAN 无限补」；失败/MARKED 也各占 1 次创邮额度
        max_attempts = max(1, int(self.target_count or 1))
        consecutive_browser_fails = 0
        deny_break_n = _ss_deny_break_n()
        switch_limit = _ss_proxy_switch_limit()
        cool_sec = _ss_cooldown_sec()
        pool_n = len(getattr(self, "_ss_proxy_pool", None) or []) or len(
            _ss_load_proxy_pool()
        )
        self.log(
            f"same_session · 数量={max_attempts}（按创邮次数停）"
            f" · 连续MARKED熔断={deny_break_n or 'off'}"
            f" · 代理池={pool_n}"
            f" · 切代理上限={switch_limit or 'off'}"
            f" · 冷却={cool_sec:.0f}s"
            f" · 当前={_ss_mask_proxy(self._current_proxy_spec())}",
            "info",
        )

        while not self.stop_event.is_set():
            # 创邮次数到顶 → 整批结束（成功+失败+MARKED 合计）
            with self._ss_attempt_lock:
                done_n = int(self.attempt_count or 0)
            if done_n >= max_attempts:
                self.log(
                    f"创邮已达数量 {done_n}/{max_attempts}"
                    f" · CLEAN {self.success_count}"
                    f" · MARKED {getattr(self, 'marked_count', 0)}"
                    f" · 过程失败 {self.fail_count} · 停批",
                    "info",
                )
                self.stop_event.set()
                return
            # 冷却窗口：连续切代理仍 deny 后等自定义秒数再继续
            if self._wait_proxy_cooldown():
                return
            # 每号取当前代理（可能被其它线程 deny 后切过）
            proxy_spec_str = self._current_proxy_spec()
            # 连续 MARKED 熔断：
            #   多代理 → 不在这里停批，等 MARKED 回调里切代理
            #   单代理/无池 → 触顶停批（旧行为）
            with self._ss_deny_lock:
                cur_deny = int(self._ss_consecutive_deny or 0)
            multi_proxy = len(getattr(self, "_ss_proxy_pool", None) or []) > 1
            # 多代理且允许切代理时，不在这里停批（由 MARKED 路径切代理/冷却）
            # 单出口 或 切代理上限=0：触顶停批
            can_rotate = multi_proxy and switch_limit > 0
            if (
                not can_rotate
                and deny_break_n > 0
                and cur_deny >= deny_break_n
            ):
                self.log(
                    f"连续 MARKED/deny {cur_deny}/{deny_break_n} · 熔断停批"
                    f"（{'切代理已关' if multi_proxy else '单出口'}，"
                    f"换出口/加池/打开切代理后再开）",
                    "error",
                )
                self.stop_event.set()
                return
            idx = self._next_ss_idx()
            # 号间抖动：压同出口短时 registration 密度（Castle deny 簇）
            # 连续 MARKED 时自动加长冷却
            jitter = _ss_inter_account_delay(self.workers, consecutive_deny=cur_deny)
            if jitter > 0 and idx > 1:
                if cur_deny > 0 and jitter >= 1.0:
                    self.log(
                        f"号间冷却 {jitter:.1f}s（连续MARKED={cur_deny}）",
                        "info",
                    )
                if self._sleep(jitter):
                    return
            # 指纹按当前代理出口国家簇锁定（防 IP↔locale 乱跳）
            fp = _ss_pick_fp(
                idx,
                proxy_spec=proxy_spec_str,
                log_fn=lambda m, lv="info": self.log(m, lv),
            )
            email = None
            try:
                # 每号开始：force 清本线程 Playwright loop，防池线程复用脏 loop
                try:
                    from g.same_session_register import (
                        _clear_thread_event_loop,
                        _drop_thread_pool,
                    )

                    _drop_thread_pool(None, reason="")
                    _clear_thread_event_loop(force=True)
                except Exception:
                    pass

                # Solver 不在线不建邮
                if not (turnstile_service.yescaptcha_key or "").strip():
                    try:
                        turnstile_service._ensure_local_solver(stop_event=self.stop_event)
                    except RuntimeError as te:
                        if str(te) == "stopped" or self.stop_event.is_set():
                            return
                        self.log(f"Solver 未就绪: {te}，等待后重试（未创建邮箱）", "warn")
                        if self._sleep(3):
                            return
                        continue
                    except Exception as se:
                        if self.stop_event.is_set():
                            return
                        self.log(f"Solver 未就绪: {se}，等待后重试", "warn")
                        if self._sleep(5):
                            return
                        continue

                # 连续浏览器/loop 炸：先歇一会再清，别狂建邮
                if consecutive_browser_fails >= 3:
                    self.log(
                        f"连续浏览器失败 {consecutive_browser_fails} 次 · "
                        f"强制清 loop 并冷却 2s（暂不建邮）",
                        "warn",
                    )
                    try:
                        from g.same_session_register import (
                            _clear_thread_event_loop,
                            _drop_thread_pool,
                            shutdown_camoufox_pool,
                        )

                        _drop_thread_pool(None, reason="连续失败")
                        _clear_thread_event_loop(force=True)
                    except Exception:
                        pass
                    if self._sleep(2.0):
                        return
                    consecutive_browser_fails = 0

                # Turnstile 预解与建邮/浏览器重叠
                ts_pre: dict[str, Any] = {
                    "token": None,
                    "error": None,
                    "t0": time.time(),
                    "done": threading.Event(),
                    "used": False,
                }

                def _ts_prewarm() -> None:
                    try:
                        task_id = turnstile_service.create_task(
                            self.site_url + "/sign-up", site_key, stop_event=self.stop_event
                        )
                        tok = turnstile_service.get_response(
                            task_id, stop_event=self.stop_event
                        )
                        ts_pre["token"] = tok
                        if not tok or tok == "CAPTCHA_FAIL":
                            ts_pre["error"] = turnstile_service.last_error or "empty"
                    except Exception as e:
                        ts_pre["error"] = str(e)
                    finally:
                        ts_pre["done"].set()

                threading.Thread(
                    target=_ts_prewarm, daemon=True, name=f"ss-ts-{idx}"
                ).start()

                try:
                    _jwt, email = email_service.create_email()
                    current_email = email
                except Exception as e:
                    # 未真正建邮成功：不占创邮额度、不记过程失败
                    self.log(f"邮箱服务异常（未建邮）: {e}", "warn")
                    if self._sleep(2):
                        return
                    continue
                if not email:
                    self.log("创建邮箱失败（未建邮）", "warn")
                    if self._sleep(1):
                        return
                    continue
                # 创邮成功即占 1 次额度（对齐 standalone：COUNT=创邮次数）
                with self._ss_attempt_lock:
                    self.attempt_count = int(self.attempt_count or 0) + 1
                    attempt_i = self.attempt_count
                # 注意：额度已占就绝不能因 stop_event 直接删邮 return。
                # 其它线程「创邮达量」停批时，本号必须继续跑完 risk/落盘。

                password = generate_random_string(14)
                given = generate_random_name()
                family = generate_random_name()
                vp = fp.get("viewport") or {}
                # 语言包跟随地区，传给 same_session（Accept-Language / navigator）
                try:
                    from g.same_session_register import locale_language_pack

                    _lp = locale_language_pack(fp.get("locale") or "en-US")
                    fp["locale"] = _lp["locale"]
                    fp["accept_language"] = _lp["accept_language"]
                    fp["languages"] = _lp["languages"]
                    fp["lang"] = _lp["lang"]
                except Exception:
                    fp.setdefault("accept_language", "")
                eg_bit = ""
                if fp.get("egress_ip") or fp.get("egress_cc"):
                    eg_bit = (
                        f" · egress={fp.get('egress_ip') or '?'}"
                        f"/{fp.get('egress_cc') or '?'}"
                        f"/{fp.get('egress_family') or '?'}"
                    )
                self.log(
                    f"开始注册[same_session]: {email} · "
                    f"[{attempt_i}/{max_attempts}] · "
                    f"{fp['tag']}/{fp['fp_os']}/{fp['timing']} · "
                    f"{fp.get('locale')}/{fp.get('timezone')} · "
                    f"al={str(fp.get('accept_language') or '')[:28]} · "
                    f"vp={vp.get('width')}x{vp.get('height')}"
                    f"{' · humanize' if fp.get('humanize') else ''} · "
                    f"px={_ss_mask_proxy(proxy_spec_str)}{eg_bit} · "
                    f"CLEAN={self.success_count} MARKED={getattr(self, 'marked_count', 0)} "
                    f"fail={self.fail_count}",
                    "info",
                )

                def fetch_code(em: str):
                    return email_service.fetch_verification_code(
                        em, stop_event=self.stop_event
                    )

                def solve_ts(sk: str):
                    if not ts_pre["done"].is_set():
                        remain = max(1.0, 90.0 - (time.time() - float(ts_pre["t0"])))
                        ts_pre["done"].wait(timeout=remain)
                    tok = ts_pre.get("token")
                    if tok and tok != "CAPTCHA_FAIL" and not ts_pre["used"]:
                        ts_pre["used"] = True
                        return tok
                    task_id = turnstile_service.create_task(
                        self.site_url + "/sign-up", sk or site_key, stop_event=self.stop_event
                    )
                    return turnstile_service.get_response(
                        task_id, stop_event=self.stop_event
                    )

                pre_token = None
                if ts_pre["done"].is_set():
                    t = ts_pre.get("token")
                    if t and t != "CAPTCHA_FAIL":
                        pre_token = t
                        ts_pre["used"] = True

                def _ss_log(msg: str, level: str = "info") -> None:
                    # same_session_register 回调只有 msg；级别固定 info
                    self.log(f"{email} {msg}", level if level in ("info", "warn", "error", "success") else "info")

                # same_session_register 的 log 只收 msg
                def _ss_log_msg(msg: str) -> None:
                    self.log(f"{email} {msg}", "info")

                ss = same_session_register(
                    email=email,
                    password=password,
                    given_name=given,
                    family_name=family,
                    fetch_code=fetch_code,
                    turnstile_token=pre_token,
                    solve_turnstile=solve_ts,
                    headless=None,
                    browser="camoufox",
                    proxy=proxy_spec_str,
                    locale=fp["locale"],
                    timezone_id=fp["timezone"],
                    fp_os=fp["fp_os"],
                    timing=fp["timing"],
                    viewport=fp["viewport"],
                    humanize=fp.get("humanize", False),
                    log=_ss_log_msg,
                )

                # 注意：创邮达量会 set stop_event，但本号若已在飞（甚至已拿 SSO）
                # 绝不能直接 return 丢号。先看结果，有 SSO 必须走 risk/落盘。
                stopped_mid = self.stop_event.is_set()

                if not ss.get("ok"):
                    err = ss.get("error") or "same_session failed"
                    err_l = str(err).lower()
                    if (
                        "asyncio loop" in err_l
                        or "sync api" in err_l
                        or "camoufox 启动" in err_l
                        or "playwright" in err_l
                    ):
                        consecutive_browser_fails += 1
                    else:
                        consecutive_browser_fails = 0
                    self._fail_account(
                        email_service, email, f"{email} same_session 失败: {err}"
                    )
                    current_email = None
                    # 已停批且本号失败：本线程退出（别再开新邮）
                    if stopped_mid:
                        return
                    # 浏览器 loop 类失败：本线程多歇一会再接下号
                    cool = 1.2 if consecutive_browser_fails else 0.3
                    if self._sleep(cool):
                        return
                    continue

                sso = (ss.get("sso") or "").strip()
                sso_rw = (ss.get("sso_rw") or sso or "").strip()
                if not sso:
                    consecutive_browser_fails = 0
                    self._fail_account(
                        email_service, email, f"{email} same_session 无 sso"
                    )
                    current_email = None
                    if stopped_mid:
                        return
                    continue
                consecutive_browser_fails = 0

                castle_len = ss.get("castle_len") or 0
                castle_method = ss.get("castle_method") or ""
                steps_tail = ""
                try:
                    steps = ss.get("steps") or []
                    if isinstance(steps, list) and steps:
                        steps_tail = " · " + " > ".join(str(x) for x in steps[-6:])
                except Exception:
                    steps_tail = ""
                if stopped_mid:
                    self.log(
                        f"{email} 停批后仍拿到 SSO · 继续 risk/落盘（不丢号）"
                        f" · castle={castle_len}/{castle_method}{steps_tail}",
                        "warn",
                    )
                else:
                    self.log(
                        f"{email} same_session SSO 到手 · castle={castle_len}"
                        f"/{castle_method}{steps_tail} · 先 risk 再决定是否计成功",
                        "info",
                    )
                # 仅 forensic 紧急盘，不写主成功文件、不进成功列表
                # （MARKED 会被绕过，绝不进 recent_success / 不导入）
                try:
                    emergency = _BASE_DIR / "keys" / "emergency_sso.txt"
                    emergency.parent.mkdir(parents=True, exist_ok=True)
                    with self.file_lock:
                        with open(emergency, "a", encoding="utf-8") as f:
                            f.write(f"{email}----{sso}\n")
                except Exception:
                    pass

                # 前台 risk 门禁：只有 CLEAN 才计成功 / 可导入；换 token 异步
                clean = self._probe_and_mark_clean(
                    email=email,
                    sso=sso,
                    sso_rw=sso_rw,
                    success_id="",
                    proxy_spec=proxy_spec_str,
                    foreground=True,
                )
                if clean is not True:
                    # MARKED / 探测失败：已写 _marked，不进成功列表、不换票、不入库
                    # MARKED 只记 marked_count，不再叠 fail_count（避免「目标5却失败7」误解）
                    if clean is False:
                        with self._ss_deny_lock:
                            self._ss_consecutive_deny = (
                                int(self._ss_consecutive_deny or 0) + 1
                            )
                            streak = self._ss_consecutive_deny
                        reason = (
                            f"{email} risk MARKED，绕过成功列表与导入"
                            f"（MARKED累计 {getattr(self, 'marked_count', 0)}"
                            f" · 连续 {streak}"
                            + (f"/{deny_break_n}" if deny_break_n else "")
                            + f" · px={_ss_mask_proxy(proxy_spec_str)}）"
                        )
                        self._fail_account(
                            email_service,
                            email,
                            reason,
                            level="warn",
                            count_fail=False,
                        )
                        # deny = 熔断信号：多代理 → 切代理；连续切 N 次仍 deny → 冷却
                        # 单代理 / 切代理关闭(switch_limit=0) → 触顶停批
                        multi = len(getattr(self, "_ss_proxy_pool", None) or []) > 1
                        action = "single"
                        if multi:
                            action = self._on_deny_rotate_proxy()
                            # cooldown：循环头 _wait_proxy_cooldown 处理
                        if action == "single" and deny_break_n > 0 and streak >= deny_break_n:
                            self.log(
                                f"连续 MARKED/deny 已达 {streak} · 熔断停批"
                                f"（{'切代理已关/单出口' if multi else '单出口'}，"
                                f"加代理池或打开切代理上限可自动轮换）",
                                "error",
                            )
                            self.stop_event.set()
                            return
                    else:
                        reason = f"{email} risk 探测失败，绕过成功列表与导入"
                        self._fail_account(
                            email_service, email, reason, level="warn"
                        )
                    current_email = None
                    # 停批后本号已收尾：退出本线程，不再开新邮
                    if stopped_mid or self.stop_event.is_set():
                        return
                    if self._sleep(0.2):
                        return
                    continue

                # —— 仅 CLEAN 路径：清零连续 MARKED + 切代理计数 ——
                with self._ss_deny_lock:
                    self._ss_consecutive_deny = 0
                with self._ss_proxy_lock:
                    self._ss_proxy_switches = 0
                ua = (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                )
                sid = self._record_success(
                    email=email,
                    sso=sso,
                    unhinged_ok=False,
                    email_service=email_service,
                    note=(
                        f"mode=same_session castle={castle_len} "
                        f"method={castle_method} risk=CLEAN"
                    ),
                    password=password,
                    already_written=False,
                    auth_token=None,
                )
                if sid:
                    self._update_success_meta(
                        sid, clean=True, note="risk=CLEAN · token=async"
                    )
                    # 换 token + 协议/NSFW 全部丢 enrich 池，主路径立刻开下一号
                    self.log(
                        f"{email} CLEAN 已计成功 · 换 token/协议/NSFW 异步处理中",
                        "info",
                    )
                    self._schedule_enrich(
                        email=email,
                        sso=sso,
                        sso_rw=sso_rw,
                        success_id=sid,
                        impersonate="chrome131",
                        user_agent=ua,
                        skip_token=False,
                    )
                elif stopped_mid:
                    # 目标已满但仍拿到 CLEAN SSO：_record_success 已写 emergency
                    self.log(
                        f"{email} CLEAN 但目标已满 · SSO 已进 emergency（不进成功列表）",
                        "warn",
                    )
                current_email = None
                # 停批后本号收尾完，退出；不 continue 再开新邮
                if stopped_mid or self.stop_event.is_set():
                    return
                continue
            except Exception as e:
                if self.stop_event.is_set():
                    if current_email:
                        try:
                            email_service.delete_email(current_email)
                        except Exception:
                            pass
                    return
                self._fail_account(
                    email_service,
                    current_email,
                    f"same_session 异常: {str(e)[:120]}",
                )
                current_email = None
                if self._sleep(1):
                    return
                continue

    def register_single_thread(self):
        # 多线程时轻微错开，单线程几乎立刻开跑
        if self.workers > 1:
            if self._sleep(random.uniform(0, min(1.5, 0.15 * self.workers))):
                return

        try:
            email_service = EmailService()
            turnstile_service = TurnstileService()
            castle_service = CastleService()
            # 协议/NSFW 已挪到后台 enrich 池，主线程不再初始化
        except Exception as e:
            self.log(f"服务初始化失败: {e}", "error")
            self.stop_event.set()
            return

        final_action_id = self.config["action_id"]
        if not final_action_id:
            self.log("线程退出：缺少 Action ID", "error")
            self.stop_event.set()
            return

        current_email = None

        # 失败只丢弃当前账号；未达目标则继续开新邮箱，直到目标或用户停止
        while not self.stop_event.is_set() and self.success_count < self.target_count:
            try:
                impersonate_fingerprint, account_user_agent = get_random_chrome_profile()
                with requests.Session(
                    impersonate=impersonate_fingerprint,
                    proxies=_configured_curl_proxies(),
                ) as session:
                    try:
                        session.get(self.site_url, timeout=8)
                    except Exception:
                        pass

                    if self.stop_event.is_set():
                        return

                    password = generate_random_string()

                    # 硬规则：Solver 不在线绝不创建邮箱，避免解不出验证码白耗配额
                    if not (turnstile_service.yescaptcha_key or "").strip():
                        try:
                            turnstile_service._ensure_local_solver(
                                stop_event=self.stop_event
                            )
                        except RuntimeError as te:
                            if str(te) == "stopped" or self.stop_event.is_set():
                                return
                            self.log(f"Solver 未就绪: {te}，等待后重试（未创建邮箱）", "warn")
                            if self._sleep(3):
                                return
                            continue
                        except Exception as se:
                            if self.stop_event.is_set():
                                return
                            self.log(
                                f"Solver 未就绪: {se}，等待后重试（未创建邮箱，不浪费配额）",
                                "warn",
                            )
                            if self._sleep(5):
                                return
                            continue

                    try:
                        jwt, email = email_service.create_email()
                        current_email = email
                    except Exception as e:
                        self._fail_account(
                            email_service, None, f"邮箱服务异常: {e}"
                        )
                        # 邮箱服务抖动：稍等再试，不整任务退出
                        if self._sleep(2):
                            return
                        continue

                    if not email:
                        self._fail_account(email_service, None, "创建邮箱失败")
                        if self._sleep(1):
                            return
                        continue

                    if self.stop_event.is_set():
                        email_service.delete_email(email)
                        current_email = None
                        return

                    self.log(f"开始注册: {email}", "info")

                    # 架构：发码/验码/注册 = 协议；Turnstile = Camoufox 无头 Solver
                    # 发码：x.ai 已迁到 REST /api/auth/send-verification-code，
                    # 该接口要求 Castle token 与页面会话 cookie 成对出现，
                    # 缺失时旧 grpc 端点仍回 grpc-status:0 但**不会真的发信**。
                    # 因此这里先用无头浏览器 mint Castle + 取 cookie，再走 JSON 发码。
                    castle_token, browser_cookies, browser_ua = None, {}, ""
                    if send_code_castle_enabled():
                        self.log(f"{email} 启动无头浏览器 mint Castle（发码必需）…", "info")
                        castle_token, browser_cookies, browser_ua = (
                            self._mint_send_code_castle()
                        )
                        if browser_cookies:
                            cookie_n = self._apply_browser_session(session, browser_cookies)
                            self.log(
                                f"{email} 已同步页面会话 cookie {cookie_n} 条（发码接口要求）",
                                "info",
                            )
                        if browser_ua:
                            account_user_agent = browser_ua
                        if not castle_token:
                            self.log(
                                f"{email} 未拿到 Castle，发码大概率会被服务端静默丢弃",
                                "warn",
                            )
                    elif castle_service.mode not in ("skip", "none", "off", "0", "false"):
                        self.log(
                            f"{email} Castle mint（mode={castle_service.mode}）…",
                            "info",
                        )
                        try:
                            castle_token = castle_service.mint(stop_event=self.stop_event)
                        except Exception as ce:
                            self.log(f"{email} Castle mint 异常: {ce}", "warn")
                            castle_token = None
                    if self.stop_event.is_set():
                        try:
                            email_service.delete_email(email)
                        except Exception:
                            pass
                        current_email = None
                        return

                    code_ok, code_reason = False, ""
                    api_res = self.send_email_code_api(
                        session,
                        email,
                        castle_request_token=castle_token,
                        user_agent=account_user_agent,
                    )
                    if api_res is None:
                        self.log(
                            f"{email} 未找到新发码接口，回退旧 grpc 端点（可能不再发信）",
                            "warn",
                        )
                        code_ok, code_reason = self.send_email_code_grpc(
                            session, email, castle_request_token=castle_token
                        )
                    else:
                        code_ok, code_reason = api_res
                    if not code_ok:
                        self._fail_account(
                            email_service,
                            email,
                            f"{email} 发送邮箱验证码失败：{code_reason or '未知原因'}",
                        )
                        current_email = None
                        continue

                    if getattr(email_service, "manual_email", ""):
                        self.log(
                            f"{email} 已请求邮箱验证码，等待人工提交流程：请把收到的验证码粘贴到「提交验证码」输入框…",
                            "warn",
                        )
                    else:
                        self.log(f"{email} 已请求邮箱验证码，等待收件…", "info")
                    verify_code = email_service.fetch_verification_code(
                        email, stop_event=self.stop_event
                    )
                    if self.stop_event.is_set():
                        try:
                            email_service.delete_email(email)
                        except Exception:
                            pass
                        current_email = None
                        return
                    if not verify_code:
                        self._fail_account(
                            email_service, email, f"{email} 未收到邮箱验证码"
                        )
                        current_email = None
                        continue

                    self.log(f"{email} 邮箱验证码: {verify_code}，提交校验…", "info")
                    verify_ok, verify_reason = True, ""
                    verify_res = self.verify_email_code_api(
                        session, email, verify_code, user_agent=account_user_agent
                    )
                    if verify_res is None:
                        verify_ok = self.verify_email_code_grpc(session, email, verify_code)
                        verify_reason = "" if verify_ok else "旧 grpc 校验失败"
                    else:
                        verify_ok, verify_reason = verify_res
                    if not verify_ok:
                        self._fail_account(
                            email_service,
                            email,
                            f"{email} 邮箱验证码校验失败（码={verify_code}）：{verify_reason or '未知原因'}",
                        )
                        current_email = None
                        continue

                    self.log(f"{email} 邮箱已通过（码={verify_code}），开始解 Turnstile…", "info")
                    signup_ok = False
                    last_turnstile_err = ""
                    # 邮箱验证码在「成功创建账号」后即失效；Turnstile 仅允许在未拿到 SSO 前重试
                    for attempt in range(1, 4):
                        if self.stop_event.is_set():
                            email_service.delete_email(email)
                            current_email = None
                            return

                        try:
                            self.log(
                                f"{email} Turnstile 第 {attempt}/3 次（Solver: {turnstile_service.solver_url}）",
                                "info",
                            )
                            task_id = turnstile_service.create_task(
                                self.site_url,
                                self.config["site_key"],
                                stop_event=self.stop_event,
                            )
                            self.log(f"{email} Turnstile 任务已创建: {str(task_id)[:18]}…", "info")
                            token = turnstile_service.get_response(
                                task_id, stop_event=self.stop_event
                            )
                        except RuntimeError as te:
                            if str(te) == "stopped" or self.stop_event.is_set():
                                try:
                                    email_service.delete_email(email)
                                except Exception:
                                    pass
                                current_email = None
                                return
                            last_turnstile_err = str(te)
                            self.log(f"{email} Turnstile 创建/查询失败: {te}", "error")
                            if self._sleep(1):
                                return
                            continue
                        except Exception as te:
                            if self.stop_event.is_set():
                                try:
                                    email_service.delete_email(email)
                                except Exception:
                                    pass
                                current_email = None
                                return
                            last_turnstile_err = str(te)
                            self.log(f"{email} Turnstile 创建/查询失败: {te}", "error")
                            if self._sleep(1):
                                return
                            continue

                        if self.stop_event.is_set() or (
                            not token and turnstile_service.last_error == "已停止"
                        ):
                            try:
                                email_service.delete_email(email)
                            except Exception:
                                pass
                            current_email = None
                            return

                        if not token or token == "CAPTCHA_FAIL":
                            err = turnstile_service.last_error or "无 token / CAPTCHA_FAIL"
                            last_turnstile_err = err
                            self.log(f"{email} Turnstile 失败: {err}", "warn")
                            if self._sleep(1):
                                return
                            continue

                        # 默认复用发码时的 Castle（同一浏览器会话，服务端才认）；
                        # 重新 mint 会换 gb_anon_id/xai_anon_id，反而丢「邮箱已验证」绑定。
                        signup_castle = castle_token
                        if (os.environ.get("GROK_SIGNUP_CASTLE_REFRESH") or "").strip() in (
                            "1",
                            "true",
                            "on",
                            "yes",
                        ):
                            try:
                                fresh = castle_service.mint(
                                    stop_event=self.stop_event,
                                    proxy=self._browser_proxy(),
                                )
                                if fresh:
                                    signup_castle = fresh
                                    self.log(
                                        f"{email} 终态 Castle 刷新 OK len={len(fresh)}",
                                        "info",
                                    )
                            except Exception as ce:
                                self.log(
                                    f"{email} 终态 Castle 刷新失败，复用旧 token: {ce}",
                                    "warn",
                                )

                        self.log(f"{email} Turnstile 成功，提交注册（协议）…", "info")
                        # 1) 新 REST 注册端点（2026-10 起）：/api/auth/sign-up/create-account
                        #    返回 session + redirectUrl，并直接下发 sso；旧 RSC /sign-up
                        #    现在只会回页面 flight 数据（无 set-cookie）。
                        api_res = self.signup_create_account_api(
                            session,
                            email=email,
                            password=password,
                            email_validation_code=verify_code,
                            turnstile_token=token,
                            castle_request_token=signup_castle,
                            user_agent=account_user_agent,
                        )
                        res = None
                        body_text = ""
                        if api_res is not None:
                            api_ok, api_reason, api_data = api_res
                            if not api_ok:
                                last_turnstile_err = f"注册被拒：{api_reason}"
                                self.log(f"{email} {last_turnstile_err}", "warn")
                                # 验证码/邮箱类错误重试无意义
                                if any(
                                    k in (api_reason or "")
                                    for k in ("验证码", "已注册", "Castle 校验失败")
                                ):
                                    break
                                if self._sleep(1):
                                    return
                                continue
                            # 跟随 cookie-chain 落 sso（部分部署只在 redirectUrl 里下发）
                            if not session.cookies.get("sso"):
                                redirect_url = str((api_data or {}).get("redirectUrl") or "")
                                if redirect_url:
                                    try:
                                        session.get(
                                            redirect_url, allow_redirects=True, timeout=15
                                        )
                                    except Exception as re_err:
                                        self.log(
                                            f"{email} 跟随 cookie-chain 失败: {re_err}",
                                            "warn",
                                        )
                        else:
                            headers = {
                                "user-agent": account_user_agent,
                                "accept": "text/x-component",
                                "content-type": "text/plain;charset=UTF-8",
                                "origin": self.site_url,
                                "referer": f"{self.site_url}/sign-up",
                                # 不要手写 cookie 头覆盖 jar：新接口要求沿用发码时的
                                # gb_anon_id / xai_anon_id / cf_clearance 等会话 cookie
                                "next-router-state-tree": self.config["state_tree"],
                                "next-action": final_action_id,
                            }
                            body_obj = {
                                "emailValidationCode": verify_code,
                                "createUserAndSessionRequest": {
                                    "email": email,
                                    "givenName": generate_random_name(),
                                    "familyName": generate_random_name(),
                                    "clearTextPassword": password,
                                    "tosAcceptedVersion": "$undefined",
                                },
                                "turnstileToken": token,
                                "conversionId": str(uuid.uuid4()),
                                "promptOnDuplicateEmail": True,
                            }
                            if signup_castle:
                                body_obj["castleRequestToken"] = signup_castle
                            payload = [body_obj]

                            try:
                                # 仅起步节流，HTTP 本身并行，避免 8 线程全卡在一把锁上
                                self._throttle_signup_post()
                                res = session.post(
                                    f"{self.site_url}/sign-up",
                                    json=payload,
                                    headers=headers,
                                    timeout=15,
                                )
                            except Exception as pe:
                                if self.stop_event.is_set():
                                    return
                                last_turnstile_err = f"提交注册异常: {pe}"
                                self.log(f"{email} 提交注册异常: {pe}", "error")
                                if self._sleep(1):
                                    return
                                continue

                            if res.status_code != 200:
                                last_turnstile_err = (
                                    f"注册 HTTP {res.status_code}: {res.text[:120]}"
                                )
                                self.log(f"{email} {last_turnstile_err}", "warn")
                                if self._sleep(1):
                                    return
                                continue

                            body_text = res.text or ""
                            # 邮箱验证码已用尽 / 失效：再解 Turnstile 也没用，立刻结束本账号
                            if (
                                "invalid-validation" in body_text
                                or "Email validation code is invalid" in body_text
                                or "email:invalid" in body_text
                            ):
                                last_turnstile_err = "邮箱验证码已失效（不可重复注册）"
                                self.log(
                                    f"{email} 邮箱验证码已失效，停止对本邮箱重试（避免空转）",
                                    "error",
                                )
                                break

                            match = re.search(
                                r'(https://[^" \s]+set-cookie\?q=[^:" \s]+)1:', body_text
                            )
                            if not match:
                                last_turnstile_err = (
                                    f"注册响应无 set-cookie: {body_text[:160]}"
                                )
                                self.log(f"{email} {last_turnstile_err}", "warn")
                                if self._sleep(1):
                                    return
                                continue

                            verify_url = match.group(1)
                            try:
                                session.get(verify_url, allow_redirects=True, timeout=12)
                            except Exception:
                                if self.stop_event.is_set():
                                    # 可能已有 cookie，尽量抢救
                                    sso_try = session.cookies.get("sso")
                                    if sso_try:
                                        self._emergency_save_sso(
                                            email, sso_try, "停止时抢救"
                                        )
                                    return
                        sso = session.cookies.get("sso")
                        sso_rw = session.cookies.get("sso-rw")
                        if not sso:
                            last_turnstile_err = "未拿到 sso cookie"
                            self.log(f"{email} 未拿到 sso cookie，重试 Turnstile", "warn")
                            if self._sleep(1):
                                return
                            continue

                        # ========== 邮箱保护硬规则 ==========
                        # 1) 拿到 SSO = xAI 账号已创建，验证码已消耗
                        # 2) 立刻落盘，后续任何失败都不得丢号、不得重注册
                        # 3) device flow / 协议 / NSFW 全部是「锦上添花」
                        sso_saved = self._emergency_save_sso(
                            email, sso, "注册完成立即落盘"
                        )
                        if not sso_saved:
                            self.log(
                                f"{email} 落盘失败，将在记成功时再写一次",
                                "error",
                            )

                        # 关键提速：SSO 到手立刻计成功并开下一号；
                        # device flow / 协议 / NSFW 全部丢后台，不堵注册主路径。
                        self.log(
                            f"{email} 已拿到 SSO（{'已落盘' if sso_saved else '落盘失败'}），"
                            f"立即记成功，device flow/协议后台处理…",
                            "info",
                        )
                        sid = self._record_success(
                            email=email,
                            sso=sso,
                            unhinged_ok=False,
                            email_service=email_service,
                            note="enrich=pending",
                            password=password,
                            already_written=sso_saved,
                            auth_token=None,
                        )
                        if sid:
                            self._schedule_enrich(
                                email=email,
                                sso=sso,
                                sso_rw=sso_rw or "",
                                success_id=sid,
                                impersonate=impersonate_fingerprint,
                                user_agent=account_user_agent,
                                # 协议/NSFW 沿用本号出口，避免换 IP 被判异常
                                proxy_spec=proxy_spec_str,
                            )
                        # SSO 已在盘上：无论是否计入目标，都算本邮箱完成
                        current_email = None
                        signup_ok = True
                        break

                    if not signup_ok:
                        if self.stop_event.is_set():
                            if current_email:
                                try:
                                    email_service.delete_email(current_email)
                                except Exception:
                                    pass
                                current_email = None
                            return
                        detail = last_turnstile_err or "Turnstile/注册失败"
                        self._fail_account(
                            email_service,
                            email,
                            f"{email} 重试 3 次后仍失败（{detail}）",
                        )
                        current_email = None
                        # 本账号失败，继续下一封新邮箱，不结束整任务
                        continue

                    # 成功且未达目标：继续下一封邮箱
                    continue

            except Exception as e:
                if self.stop_event.is_set():
                    if current_email:
                        try:
                            email_service.delete_email(current_email)
                        except Exception:
                            pass
                    return
                self._fail_account(
                    email_service,
                    current_email,
                    f"异常: {str(e)[:120]}",
                )
                current_email = None
                if self._sleep(1):
                    return
                continue

    def _run_workers(self, workers: int):
        try:
            if not self.initialize():
                return
            if self.stop_event.is_set():
                self.status = "done"
                self.log("任务已取消（初始化后停止）", "warn")
                return
            self.status = "running"
            mode = resolve_register_mode(getattr(self, "register_mode", None))
            self.register_mode = mode
            worker_fn = (
                self.register_single_thread_same_session
                if mode == "same_session"
                else self.register_single_thread
            )
            if mode == "same_session":
                self.log(
                    f"启动 {workers} 线程 · 创邮数量 {self.target_count}"
                    f"（失败/MARKED 也占 1 次）· 路径={mode}",
                    "info",
                )
            else:
                self.log(
                    f"启动 {workers} 个线程，目标 CLEAN {self.target_count} 个 · 路径={mode}",
                    "info",
                )
            self.log(f"输出: {self.output_file}", "info")
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                self._executor = executor
                futures = [executor.submit(worker_fn) for _ in range(workers)]
                # 周期检查 stop，避免 wait 一直挂到所有线程自然结束才有反馈
                while True:
                    done, _not_done = concurrent.futures.wait(
                        futures, timeout=0.5, return_when=concurrent.futures.ALL_COMPLETED
                    )
                    if len(done) == len(futures):
                        break
                    if self.stop_event.is_set() and self.status == "stopping":
                        # 再等一小会儿让线程看到 stop_event 退出；最长约 6s
                        concurrent.futures.wait(futures, timeout=6)
                        break
            self._executor = None
            # 等后台 NSFW/协议收尾（最多 ~45s）
            try:
                deadline = time.time() + 45.0
                while time.time() < deadline:
                    with self._enrich_lock:
                        pending = self._enrich_pending
                    if pending <= 0:
                        break
                    time.sleep(0.5)
                with self._enrich_lock:
                    left = self._enrich_pending
                # 统计时：有可用 token 或已导入都算「票已就绪」（导入后会清内存 token）
                token_ready = 0
                imported_n = 0
                for it in list(self.recent_success):
                    if it.get("imported"):
                        imported_n += 1
                        token_ready += 1
                    elif is_auth_token_usable(it.get("auth_token")):
                        token_ready += 1
                if left > 0:
                    self.log(
                        f"仍有 {left} 个后台 NSFW/协议未完成；token 就绪 "
                        f"{token_ready}/{self.success_count}"
                        f"（不自动入库，页面手动导入）",
                        "warn",
                    )
                else:
                    self.log(
                        f"流水线收尾：token 就绪 {token_ready}/{self.success_count}"
                        f"（不自动入库 · 点「导入」手动入库）",
                        "success" if token_ready else "warn",
                    )
            except Exception:
                pass
            # 主流程不自动入库：CLEAN/token 只落盘 + recent_success，
            # 入库改由页面「导入」手动点（避免跑完就直写 sub2api）
            # same_session 浏览器池收尾
            if resolve_register_mode(getattr(self, "register_mode", None)) == "same_session":
                try:
                    from g.same_session_register import shutdown_camoufox_pool

                    shutdown_camoufox_pool()
                except Exception:
                    pass
            if self.status == "error":
                pass
            else:
                self.status = "done"
                # 口径：数量=创邮次数；CLEAN/MARKED/过程失败分开计
                attempts = int(getattr(self, "attempt_count", 0) or 0)
                self.log(
                    f"任务结束：创邮 {attempts}/{self.target_count}"
                    f" · CLEAN {self.success_count}"
                    f" · 过程失败 {self.fail_count}"
                    f" · MARKED {getattr(self, 'marked_count', 0)}"
                    f" · 连续MARKED {getattr(self, '_ss_consecutive_deny', 0)}",
                    "success" if self.success_count else "warn",
                )
        except Exception as e:
            self.error_message = str(e)
            self.status = "error"
            self.log(f"运行失败: {e}", "error")
        finally:
            self.stop_event.set()
            if self.status not in ("done", "error"):
                self.status = "done"
            # 钉死耗时：结束后前端轮询不再让「已用时间」空转
            self._freeze_elapsed()
            # 任务结束即停看门狗，避免空闲时反复拉起已崩溃的 Solver
            try:
                import solver_manager

                solver_manager.stop_watchdog()
            except Exception:
                pass

    def _auto_import_clean_accounts(self) -> None:
        """
        任务收尾自动入库：
        1) 优先 recent_success 里未导入且有缓存 token 的 CLEAN 号（直写）
        2) 若内存已全部 imported，跳过（避免再读 clean 文件走 sso-to-oauth 二次导入）
        3) 仅当内存空/缺票时，才回落 _clean.txt
        """
        from g.auto_import import auto_import_enabled

        if not auto_import_enabled():
            self.log("自动入库已关闭（AUTO_IMPORT=0）", "info")
            return

        pending = [
            it
            for it in list(self.recent_success)
            if it.get("sso")
            and not it.get("imported")
            and (it.get("clean") is True or it.get("clean") is None)
        ]
        already = sum(1 for it in list(self.recent_success) if it.get("imported"))
        if not pending and already > 0:
            self.log(
                f"自动入库跳过：{already} 条已在任务内直写导入，无需再读 clean 文件",
                "success",
            )
            return

        if pending:
            try:
                from app import import_sso_to_upstream
            except Exception as e:
                self.log(f"自动入库失败：无法加载导入模块 · {e}", "error")
                return
            accounts = []
            seen = set()
            for it in pending:
                sso = (it.get("sso") or "").strip()
                if not sso or sso in seen:
                    continue
                seen.add(sso)
                tok = it.get("auth_token")
                accounts.append(
                    {
                        "email": (it.get("email") or "").strip(),
                        "sso": sso,
                        "auth_token": tok if isinstance(tok, dict) else None,
                    }
                )
            if not accounts:
                self.log("自动入库跳过：无可提交账号", "warn")
                return
            cached_n = sum(
                1 for a in accounts if is_auth_token_usable(a.get("auth_token"))
            )
            self.log(
                f"自动入库开始 · recent_success {len(accounts)} 条"
                f"（缓存 token {cached_n}）",
                "info",
            )
            result = import_sso_to_upstream(
                accounts=accounts, merge=True, max_workers=1
            )
            # 标记已导入，清内存 token（与 app._mark_recent_imported 对齐）
            ok_emails = set()
            for row in result.get("results") or []:
                if row.get("status") == "ok" and row.get("email"):
                    ok_emails.add(str(row["email"]).lower())
            if result.get("ok") or (result.get("success") or 0) > 0:
                for it in self.recent_success:
                    em = (it.get("email") or "").lower()
                    if em and em in ok_emails:
                        it["imported"] = True
                        it["auth_token"] = None
                    elif result.get("ok") and it in pending:
                        it["imported"] = True
                        it["auth_token"] = None
            success = int(result.get("success") or 0)
            fail = int(result.get("fail") or 0)
            msg = result.get("message") or ""
            level = (
                "success"
                if success > 0 and fail == 0
                else ("warn" if success > 0 else "error")
            )
            self.log(
                f"自动入库完成 · 成功 {success}/{len(accounts)} · 失败 {fail} · {msg}",
                level,
            )
            return

        # 回落：内存无账号时读 clean 文件（例如仅 CLI 跑完、或 recent 被清）
        if not self.output_file:
            self.log("自动入库跳过：无 output 与 recent", "warn")
            return
        try:
            from g.auto_import import import_clean_file

            clean_file = Path(self.output_file).with_name(
                Path(self.output_file).stem + "_clean.txt"
            )
            if clean_file.is_file() and clean_file.stat().st_size > 0:
                import_clean_file(
                    clean_file,
                    log=lambda msg, level="info": self.log(msg, level),
                )
            else:
                self.log("无 CLEAN 文件，跳过自动入库", "warn")
        except Exception as ie:
            self.log(f"自动入库（文件回落）异常: {ie}", "warn")

    def stop(self) -> dict:
        if not self.is_running():
            return {"ok": False, "message": "当前没有运行中的任务", **self.get_status()}
        self.status = "stopping"
        self.stop_event.set()
        self.log("正在停止任务（等待当前网络请求结束，最多约数秒）…", "warn")
        return {"ok": True, "message": "已发送停止信号", **self.get_status()}

    def start(
        self,
        workers: int = 8,
        target: int = 100,
        blocking: bool = False,
        mode: Optional[str] = None,
    ) -> dict:
        with self._run_lock:
            # 线程还没跑到 initialize 时 status 也要立刻占位，防止重复启动
            if self.is_running() or (
                self._worker_thread is not None and self._worker_thread.is_alive()
            ):
                return {"ok": False, "message": "任务已在运行中", **self.get_status()}

            workers = max(1, min(int(workers), 64))
            target = max(1, int(target))
            # same_session 吃浏览器资源，默认压并发上限
            reg_mode = resolve_register_mode(
                mode if mode is not None else os.environ.get("GROK_REGISTER_MODE")
            )
            if reg_mode == "same_session":
                max_ss = int(os.environ.get("GROK_SS_MAX_WORKERS") or "4")
                max_ss = max(1, min(max_ss, 16))
                if workers > max_ss:
                    self.log(
                        f"same_session 并发 {workers}→{max_ss}（GROK_SS_MAX_WORKERS，防浏览器打爆）",
                        "warn",
                    )
                    workers = max_ss

            self.stop_event.clear()
            self.success_count = 0
            self.fail_count = 0
            self.clean_count = 0
            self.marked_count = 0
            self.attempt_count = 0
            self._ss_consecutive_deny = 0
            self.target_count = target
            self.workers = workers
            self.register_mode = reg_mode
            self._ss_idx = 0
            self.start_time = time.time()
            self.end_time = None  # 新一轮重新计时
            self.error_message = ""
            self.recent_success.clear()
            # 装载代理池（deny 熔断切代理 / 冷却）
            self._init_proxy_pool()
            # 先标 initializing，避免并发 /api/start 重复拉起
            self.status = "initializing"
            # 不清空缓存的 action_id；initialize 会优先用缓存
            if not self.config.get("action_id") and self._action_cache.get("action_id"):
                self._apply_action_cache()

            os.makedirs("keys", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            prefix = "grok_ss" if reg_mode == "same_session" else "grok"
            self.output_file = f"keys/{prefix}_{timestamp}_{target}.txt"
            self.credentials_file = f"keys/{prefix}_{timestamp}_{target}_credentials.csv"

            if blocking:
                self._run_workers(workers)
                return {"ok": True, "message": "任务完成", **self.get_status()}

            self._worker_thread = threading.Thread(
                target=self._run_workers,
                args=(workers,),
                daemon=True,
                name="RegisterEngine",
            )
            self._worker_thread.start()
            return {
                "ok": True,
                "message": f"任务已启动（路径={reg_mode}）",
                **self.get_status(),
            }


# 兼容旧 CLI 全局入口
_cli_logs = LogBuffer()
engine = RegisterEngine(log_fn=lambda msg, level="info": _cli_logs.emit(msg, level))


def main():
    print("=" * 60 + "\nGrok 注册机\n" + "=" * 60)
    default_mode = resolve_register_mode()
    print(f"注册路径: protocol=协议主路径（默认，REST 发码/验码/注册） / same_session=同会话浏览器")
    print(f"当前默认: {default_mode}（可用环境变量 GROK_REGISTER_MODE 覆盖）")
    mode_in = input(f"\n路径 (默认 {default_mode}): ").strip() or default_mode
    mode = resolve_register_mode(mode_in)
    try:
        t = int(input("\n并发数 (默认4): ").strip() or 4)
    except Exception:
        t = 4
    try:
        total = int(input("注册数量 (默认10): ").strip() or 10)
    except Exception:
        total = 10
    engine.start(workers=t, target=total, blocking=True, mode=mode)


if __name__ == "__main__":
    main()
