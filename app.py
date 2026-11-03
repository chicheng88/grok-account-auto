"""
Grok 注册机 Web 控制台
启动: python app.py
浏览器打开 http://127.0.0.1:3333
"""
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory

from grok import LogBuffer, RegisterEngine
import solver_manager

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

load_dotenv(ENV_PATH)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))

# 主流程日志（建邮/camoufox/castle/发码/signup/SSO…）
logs = LogBuffer(maxlen=3000)
# 右侧副区：risk 探测 + 换 token（不进主日志，避免刷屏）
post_logs = LogBuffer(maxlen=2000)


def _is_post_process_log(message: str) -> bool:
    """
    risk / 换 token / 协议 / NSFW 相关日志 → 右侧副区。
    主区只保留注册主路径，便于盯吞吐。
    注意：主路径「CLEAN 已计成功 · 换 token/协议/NSFW 异步处理中」仍留主区。
    """
    msg = str(message or "")
    if not msg:
        return False
    # 主路径宣告异步，不当后置步骤
    if "异步处理中" in msg and "CLEAN" in msg:
        return False
    # 换 token 操作本身 / device flow
    if re.search(
        r"换\s*token\s*(开始|成功|失败|异常|返回体|：|：approve)|"
        r"\[后台\]\s*换\s*token|"
        r"device\s*flow|"
        r"device_flow",
        msg,
        re.I,
    ):
        return True
    # 协议 / NSFW / unhinged（enrich 后置）
    if re.search(
        r"\[后台\].*(NSFW|unhinged|协议)|"
        r"\bNSFW\b|"
        r"unhinged|"
        r"协议/NSFW|"
        r"协议失败|"
        r"NSFW失败|"
        r"token=async|"
        r"enrich",
        msg,
        re.I,
    ):
        return True
    # risk 探测全链路（含 MARKED/CLEAN/INFRA/调度）
    if re.search(
        r"\brisk\s*(探测|CLEAN|MARKED|INFRA|跳过|基建)|"
        r"risk\s+CLEAN|"
        r"risk\s+MARKED|"
        r"risk\s+INFRA|"
        r"调度\s*risk|"
        r"绕过成功列表",
        msg,
        re.I,
    ):
        return True
    return False


def _route_engine_log(msg: str, level: str = "info") -> None:
    if _is_post_process_log(msg):
        post_logs.emit(msg, level)
    else:
        logs.emit(msg, level)


engine = RegisterEngine(log_fn=_route_engine_log)

CONFIG_KEYS = (
    "WORKER_DOMAIN",
    "FREEMAIL_TOKEN",
    "FREEMAIL_DOMAIN",
    "FREEMAIL_API_STYLE",
    "YESCAPTCHA_KEY",
    "SOLVER_URL",
    "SOLVER_BROWSER",
    "SOLVER_THREADS",
    "SOLVER_HOST",
    "SOLVER_PORT",
    "SOLVER_DEBUG",
    "UI_HOST",
    "UI_PORT",
    "SUB2API_URL",
    "SUB2API_DOCKER_CONTAINER",
    "SUB2API_DB_HOST",
    "SUB2API_DB_PORT",
    "SUB2API_DB_NAME",
    "SUB2API_DB_USER",
    "SUB2API_DB_PASSWORD",
    "SUB2API_GROK_GROUP_ID",
    "SUB2API_GROK_GROUP_NAME",
    "UPSTREAM_URL",
    "UPSTREAM_ADMIN_EMAIL",
    "UPSTREAM_ADMIN_PASSWORD",
    "GROK_PROXY",
    "GROK_PROXY_LIST",
    "GROK_SS_DENY_BREAK",
    "GROK_SS_PROXY_SWITCH_LIMIT",
    "GROK_SS_COOLDOWN_SEC",
)

DEFAULTS = {
    "WORKER_DOMAIN": "",
    "FREEMAIL_TOKEN": "",
    "FREEMAIL_DOMAIN": "auto",
    "FREEMAIL_API_STYLE": "auto",
    "YESCAPTCHA_KEY": "",
    "SOLVER_URL": "http://127.0.0.1:5072",
    "SOLVER_BROWSER": "camoufox",
    "SOLVER_THREADS": "4",
    "SOLVER_HOST": "127.0.0.1",
    "SOLVER_PORT": "5072",
    "SOLVER_DEBUG": "1",
    "UI_HOST": "127.0.0.1",
    "UI_PORT": "3333",
    "SUB2API_URL": "http://127.0.0.1:9898",
    "SUB2API_DOCKER_CONTAINER": "sub2api",
    "SUB2API_DB_HOST": "postgres",
    "SUB2API_DB_PORT": "5432",
    "SUB2API_DB_NAME": "sub2api",
    "SUB2API_DB_USER": "ige",
    "SUB2API_DB_PASSWORD": "ige_pass",
    "SUB2API_GROK_GROUP_ID": "23",
    "SUB2API_GROK_GROUP_NAME": "grok",
    "UPSTREAM_URL": "http://127.0.0.1:9898",
    "UPSTREAM_ADMIN_EMAIL": "",
    "UPSTREAM_ADMIN_PASSWORD": "",
    # 注册代理：空=直连；支持 host:port / http://host:port / user:pass@host:port / host:port:user:pass
    "GROK_PROXY": "",
    # 多行代理池（优先于 GROK_PROXY）；换行/逗号/分号分隔
    "GROK_PROXY_LIST": "",
    # 熔断：单代理连续 deny 停批阈值；0=off（多代理时优先切代理，不靠这个停）
    "GROK_SS_DENY_BREAK": "3",
    # deny 后连续切换代理次数上限，触顶进入冷却
    "GROK_SS_PROXY_SWITCH_LIMIT": "3",
    # 冷却秒数（连续切代理仍 deny 后等待再继续）
    "GROK_SS_COOLDOWN_SEC": "60",
}


def read_env_file() -> dict:
    data = dict(DEFAULTS)
    if not ENV_PATH.exists():
        # fallback to process env
        for k in CONFIG_KEYS:
            data[k] = os.getenv(k, data[k]) or data[k]
        return data

    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, val = raw.split("=", 1)
        key = key.strip()
        if key in CONFIG_KEYS:
            data[key] = val.strip().strip('"').strip("'")
    # process env overrides missing blanks only for runtime consistency
    for k in CONFIG_KEYS:
        if not data.get(k):
            data[k] = os.getenv(k, data.get(k, "")) or data.get(k, "")
    return data


def write_env_file(values: dict) -> None:
    existing_lines = []
    if ENV_PATH.exists():
        existing_lines = ENV_PATH.read_text(encoding="utf-8").splitlines()

    written = set()
    out = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in values:
            if key in written:
                # Keep one canonical entry when a prior partial save left duplicates.
                continue
            out.append(f"{key}={values[key]}")
            written.add(key)
        else:
            out.append(line)

    # append missing keys
    for key in CONFIG_KEYS:
        if key in values and key not in written:
            if out and out[-1].strip():
                out.append("")
            out.append(f"{key}={values.get(key, DEFAULTS.get(key, ''))}")

    # ensure example comments if file was empty
    if not existing_lines:
        out = [
            "# freemail API 配置",
            f"WORKER_DOMAIN={values.get('WORKER_DOMAIN', '')}",
            f"FREEMAIL_TOKEN={values.get('FREEMAIL_TOKEN', '')}",
            f"FREEMAIL_DOMAIN={values.get('FREEMAIL_DOMAIN', DEFAULTS['FREEMAIL_DOMAIN'])}",
            f"FREEMAIL_API_STYLE={values.get('FREEMAIL_API_STYLE', DEFAULTS['FREEMAIL_API_STYLE'])}",
            "",
            "# Turnstile 验证配置",
            "# 如果不填则使用本地 Turnstile Solver",
            f"YESCAPTCHA_KEY={values.get('YESCAPTCHA_KEY', '')}",
            f"SOLVER_URL={values.get('SOLVER_URL', DEFAULTS['SOLVER_URL'])}",
            f"SOLVER_BROWSER={values.get('SOLVER_BROWSER', DEFAULTS['SOLVER_BROWSER'])}",
            f"SOLVER_THREADS={values.get('SOLVER_THREADS', DEFAULTS['SOLVER_THREADS'])}",
            f"SOLVER_HOST={values.get('SOLVER_HOST', DEFAULTS['SOLVER_HOST'])}",
            f"SOLVER_PORT={values.get('SOLVER_PORT', DEFAULTS['SOLVER_PORT'])}",
            f"SOLVER_DEBUG={values.get('SOLVER_DEBUG', DEFAULTS['SOLVER_DEBUG'])}",
            "",
            "# Web 控制台",
            f"UI_HOST={values.get('UI_HOST', DEFAULTS['UI_HOST'])}",
            f"UI_PORT={values.get('UI_PORT', DEFAULTS['UI_PORT'])}",
            "",
            "# 注册代理（空=直连；池用分号分隔）",
            f"GROK_PROXY={values.get('GROK_PROXY', DEFAULTS.get('GROK_PROXY', ''))}",
            f"GROK_PROXY_LIST={values.get('GROK_PROXY_LIST', DEFAULTS.get('GROK_PROXY_LIST', ''))}",
            f"GROK_SS_DENY_BREAK={values.get('GROK_SS_DENY_BREAK', DEFAULTS.get('GROK_SS_DENY_BREAK', '3'))}",
            f"GROK_SS_PROXY_SWITCH_LIMIT={values.get('GROK_SS_PROXY_SWITCH_LIMIT', DEFAULTS.get('GROK_SS_PROXY_SWITCH_LIMIT', '3'))}",
            f"GROK_SS_COOLDOWN_SEC={values.get('GROK_SS_COOLDOWN_SEC', DEFAULTS.get('GROK_SS_COOLDOWN_SEC', '60'))}",
            "",
            "# sub2api Grok（成功账号导入）",
            f"SUB2API_URL={values.get('SUB2API_URL', DEFAULTS['SUB2API_URL'])}",
            f"SUB2API_DOCKER_CONTAINER={values.get('SUB2API_DOCKER_CONTAINER', DEFAULTS['SUB2API_DOCKER_CONTAINER'])}",
            f"SUB2API_DB_HOST={values.get('SUB2API_DB_HOST', DEFAULTS['SUB2API_DB_HOST'])}",
            f"SUB2API_DB_PORT={values.get('SUB2API_DB_PORT', DEFAULTS['SUB2API_DB_PORT'])}",
            f"SUB2API_DB_NAME={values.get('SUB2API_DB_NAME', DEFAULTS['SUB2API_DB_NAME'])}",
            f"SUB2API_DB_USER={values.get('SUB2API_DB_USER', DEFAULTS['SUB2API_DB_USER'])}",
            f"SUB2API_DB_PASSWORD={values.get('SUB2API_DB_PASSWORD', DEFAULTS['SUB2API_DB_PASSWORD'])}",
            f"SUB2API_GROK_GROUP_ID={values.get('SUB2API_GROK_GROUP_ID', DEFAULTS['SUB2API_GROK_GROUP_ID'])}",
            f"SUB2API_GROK_GROUP_NAME={values.get('SUB2API_GROK_GROUP_NAME', DEFAULTS['SUB2API_GROK_GROUP_NAME'])}",
            f"UPSTREAM_URL={values.get('UPSTREAM_URL', values.get('SUB2API_URL', DEFAULTS['SUB2API_URL']))}",
            f"UPSTREAM_ADMIN_EMAIL={values.get('UPSTREAM_ADMIN_EMAIL', '')}",
            f"UPSTREAM_ADMIN_PASSWORD={values.get('UPSTREAM_ADMIN_PASSWORD', '')}",
            "",
        ]

    ENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def _split_proxy_lines(raw: str) -> list[str]:
    """把代理池文本拆成行：支持换行 / 逗号 / 分号；忽略 # 注释与空行。"""
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    parts: list[str] = []
    for chunk in re.split(r"[\n,;]+", text):
        line = chunk.strip()
        if not line or line.startswith("#"):
            continue
        parts.append(line)
    # 去重保序
    seen = set()
    out: list[str] = []
    for p in parts:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _normalize_proxy_list_text(raw: str) -> str:
    """规范化代理池：一行一个，便于前端 textarea 回显。"""
    return "\n".join(_split_proxy_lines(raw))


def _proxy_list_for_env(raw: str) -> str:
    """落盘 .env：单行，分号分隔（.env 不支持裸多行值）。"""
    return ";".join(_split_proxy_lines(raw))


def _primary_proxy_from_values(proxy_list: str, single: str) -> str:
    """池优先；否则单条 GROK_PROXY。"""
    lines = _split_proxy_lines(proxy_list)
    if lines:
        return lines[0]
    return (single or "").strip()


def _proxy_display_name(raw: str, parsed: dict | None = None) -> str:
    """Return a proxy label without ever sending credentials back to the UI."""
    info = parsed or {}
    server = str(info.get("server") or "").strip()
    if server:
        return server
    # The fallback also covers a parser that accepts an unusual URL form.
    return re.sub(r"//[^/@]+@", "//", (raw or "").strip())[:160]


def _probe_register_proxy(raw: str, *, timeout: float = 12.0) -> dict:
    """Check proxy egress and xAI reachability without leaking proxy credentials."""
    raw = (raw or "").strip()
    timeout = max(3.0, min(float(timeout or 12.0), 45.0))
    started = time.monotonic()
    result = {
        "ok": False,
        "proxy": "(direct)" if not raw else "",
        "egress_ok": False,
        "egress_ip": "",
        "egress_label": "",
        "egress_source": "",
        "egress_ms": 0,
        "egress_error": "",
        "xai_ok": False,
        "xai_status": 0,
        "xai_ms": 0,
        "error": "",
        "message": "",
        "ms": 0,
    }

    proxies = None
    if raw:
        try:
            from g.same_session_register import parse_proxy_spec

            parsed = parse_proxy_spec(raw)
            if not parsed:
                raise ValueError("代理格式无法解析")
            proxy_url = str(parsed.get("server_url") or parsed.get("server") or "").strip()
            if not proxy_url:
                raise ValueError("代理地址为空")
            result["proxy"] = _proxy_display_name(raw, parsed)
            proxies = {"http": proxy_url, "https": proxy_url}
        except Exception as exc:
            message = str(exc) or "代理格式无法解析"
            result.update({
                "error": message[:180],
                "message": f"代理配置无效：{message[:120]}",
            })
            result["ms"] = round((time.monotonic() - started) * 1000)
            return result

    try:
        from curl_cffi import requests as http_requests
    except Exception as exc:
        message = f"curl_cffi 不可用：{exc}"
        result.update({"error": message[:180], "message": message[:160]})
        result["ms"] = round((time.monotonic() - started) * 1000)
        return result

    # IP geolocation services occasionally rate-limit. A plain IP endpoint is a
    # deliberate fallback so an otherwise usable proxy is not reported as dead.
    egress_started = time.monotonic()
    egress_errors: list[str] = []
    for url, source in (
        ("https://ipapi.co/json/", "ipapi"),
        ("https://api64.ipify.org?format=json", "ipify"),
    ):
        try:
            response = http_requests.get(
                url,
                proxies=proxies,
                timeout=timeout,
                impersonate="chrome124",
            )
            status = int(getattr(response, "status_code", 0) or 0)
            if not 200 <= status < 300:
                raise RuntimeError(f"{source} HTTP {status}")
            data = response.json()
            ip = str(data.get("ip") or data.get("query") or "").strip()
            if not ip:
                raise RuntimeError(f"{source} 未返回出口 IP")
            cc = str(data.get("country_code") or data.get("countryCode") or "").upper()
            city = str(data.get("city") or "").strip()
            country = str(data.get("country_name") or data.get("country") or "").strip()
            label = " / ".join(x for x in (ip, cc, city or country) if x)
            result.update({
                "egress_ok": True,
                "egress_ip": ip,
                "egress_label": label or ip,
                "egress_source": source,
                "egress_ms": round((time.monotonic() - egress_started) * 1000),
            })
            break
        except Exception as exc:
            egress_errors.append(f"{source}: {str(exc)[:100]}")
    if not result["egress_ok"]:
        result["egress_ms"] = round((time.monotonic() - egress_started) * 1000)
        result["egress_error"] = "; ".join(egress_errors)[:220]

    xai_started = time.monotonic()
    try:
        response = http_requests.get(
            "https://accounts.x.ai/",
            proxies=proxies,
            timeout=timeout,
            impersonate="chrome124",
            allow_redirects=True,
        )
        status = int(getattr(response, "status_code", 0) or 0)
        result["xai_status"] = status
        # Any HTTP response below 500 proves the proxy reached xAI. A 401/403 is
        # meaningful application feedback, not a TCP/proxy failure.
        result["xai_ok"] = 100 <= status < 500
        if not result["xai_ok"]:
            result["error"] = f"xAI HTTP {status}"
    except Exception as exc:
        result["error"] = f"xAI 请求失败：{str(exc)[:180]}"
    result["xai_ms"] = round((time.monotonic() - xai_started) * 1000)
    result["ms"] = round((time.monotonic() - started) * 1000)
    result["ok"] = bool(result["xai_ok"])
    if result["ok"]:
        result["message"] = f"xAI 连通（HTTP {result['xai_status']}）"
    elif result["egress_ok"]:
        result["message"] = result["error"] or "出口可用，但 xAI 不可达"
    else:
        result["message"] = result["error"] or result["egress_error"] or "代理出口探测失败"
    return result


def _split_mail_domains(raw: str) -> list[str]:
    """邮箱后缀多选：逗号/分号/空白分隔；auto 单独表示服务端默认。"""
    text = (raw or "").strip()
    if not text:
        return ["auto"]
    parts: list[str] = []
    for chunk in re.split(r"[,;\s]+", text):
        d = chunk.strip().lower()
        if not d:
            continue
        if d in ("auto", "default", "随机", "自动"):
            # 有其它域名时忽略 auto；仅 auto 时保留
            continue
        if d not in parts:
            parts.append(chunk.strip())  # 保留原始大小写域名
    if not parts:
        return ["auto"]
    return parts


def _normalize_mail_domains(raw: str) -> str:
    """落盘：逗号分隔；单 auto 就写 auto。"""
    domains = _split_mail_domains(raw)
    if domains == ["auto"]:
        return "auto"
    return ",".join(domains)


def _sync_proxy_env_aliases() -> None:
    """
    同步代理到注册链路别名。
    优先 GROK_PROXY_LIST 首条 → GROK_PROXY；空则清掉别名。
    完整池仍由 GROK_PROXY_LIST 环境变量提供给引擎轮换。
    注意：进程环境里的池必须用分号单行，禁止写换行（部分宿主/dotenv 会截断）。
    """
    raw_pool = os.environ.get("GROK_PROXY_LIST") or ""
    lines = _split_proxy_lines(raw_pool)
    single = (os.environ.get("GROK_PROXY") or "").strip()
    primary = lines[0] if lines else (single or "").strip()
    if lines:
        os.environ["GROK_PROXY_LIST"] = _proxy_list_for_env("\n".join(lines))
    elif "GROK_PROXY_LIST" in os.environ and not raw_pool.strip():
        os.environ["GROK_PROXY_LIST"] = ""
    for alias in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY", "GROK_SAME_SESSION_PROXY"):
        if primary:
            os.environ[alias] = primary
        else:
            os.environ.pop(alias, None)
    # STANDALONE / same_session 也会读这些
    if primary:
        os.environ["STANDALONE_LOCAL_PROXY"] = primary
        os.environ["LOCAL_PROXY"] = primary
    else:
        os.environ.pop("STANDALONE_LOCAL_PROXY", None)
        os.environ.pop("LOCAL_PROXY", None)


def apply_env_to_process(values: dict) -> None:
    for k, v in values.items():
        os.environ[k] = v or ""
    # reload dotenv for any other readers
    load_dotenv(ENV_PATH, override=True)
    # 以最终进程环境为准再同步代理别名（避免 dotenv 覆盖后别名不一致）
    if "GROK_PROXY" in values:
        os.environ["GROK_PROXY"] = str(values.get("GROK_PROXY") or "").strip()
    if "GROK_PROXY_LIST" in values:
        os.environ["GROK_PROXY_LIST"] = _proxy_list_for_env(
            str(values.get("GROK_PROXY_LIST") or "")
        )
    for fuse_key in (
        "GROK_SS_DENY_BREAK",
        "GROK_SS_PROXY_SWITCH_LIMIT",
        "GROK_SS_COOLDOWN_SEC",
    ):
        if fuse_key in values:
            os.environ[fuse_key] = str(values.get(fuse_key) or "").strip()
    _sync_proxy_env_aliases()


def env_snapshot():
    cfg = read_env_file()
    worker = cfg.get("WORKER_DOMAIN", "").strip()
    token = cfg.get("FREEMAIL_TOKEN", "").strip()
    yes = cfg.get("YESCAPTCHA_KEY", "").strip()
    mail_domain = (cfg.get("FREEMAIL_DOMAIN") or DEFAULTS["FREEMAIL_DOMAIN"]).strip() or "auto"
    sub2 = get_sub2api_config_from_cfg(cfg)
    sub2_url = sub2["url"]
    admin_email = sub2.get("admin_email") or ""
    admin_password = sub2.get("admin_password") or ""
    # HTTP 导入：URL + 管理员账号密码 + 分组名称（ID 运行时自动解析）
    configured = bool(sub2_url and admin_email and admin_password and sub2["group_name"])
    return {
        "worker_domain_set": bool(worker),
        "freemail_token_set": bool(token),
        "yescaptcha_set": bool(yes),
        "worker_domain": worker,
        "freemail_domain": mail_domain,
        "solver_url": cfg.get("SOLVER_URL") or DEFAULTS["SOLVER_URL"],
        "solver_browser": cfg.get("SOLVER_BROWSER") or DEFAULTS["SOLVER_BROWSER"],
        "solver_threads": cfg.get("SOLVER_THREADS") or DEFAULTS["SOLVER_THREADS"],
        "ui_host": cfg.get("UI_HOST") or DEFAULTS["UI_HOST"],
        "ui_port": cfg.get("UI_PORT") or DEFAULTS["UI_PORT"],
        "grok_proxy": (cfg.get("GROK_PROXY") or "").strip(),
        "grok_proxy_set": bool(
            (cfg.get("GROK_PROXY") or "").strip()
            or (cfg.get("GROK_PROXY_LIST") or "").strip()
        ),
        "grok_proxy_list": _normalize_proxy_list_text(cfg.get("GROK_PROXY_LIST") or ""),
        "grok_proxy_count": (
            len(_split_proxy_lines(cfg.get("GROK_PROXY_LIST") or ""))
            or (1 if (cfg.get("GROK_PROXY") or "").strip() else 0)
        ),
        "ss_deny_break": (cfg.get("GROK_SS_DENY_BREAK") or DEFAULTS["GROK_SS_DENY_BREAK"]).strip(),
        "ss_proxy_switch_limit": (
            cfg.get("GROK_SS_PROXY_SWITCH_LIMIT") or DEFAULTS["GROK_SS_PROXY_SWITCH_LIMIT"]
        ).strip(),
        "ss_cooldown_sec": (
            cfg.get("GROK_SS_COOLDOWN_SEC") or DEFAULTS["GROK_SS_COOLDOWN_SEC"]
        ).strip(),
        "sub2api_url": sub2_url,
        "sub2api_container": sub2["container"],
        "sub2api_group_id": sub2["group_id"],
        "sub2api_group_name": sub2["group_name"],
        "sub2api_configured": configured,
        "upstream_admin_email": admin_email,
        # legacy names consumed by existing UI
        "upstream_url": sub2_url,
        "upstream_configured": configured,
        "upstream_password_set": bool(admin_password),
    }


def normalize_upstream_url(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if not u:
        return ""
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u.rstrip("/")


def get_upstream_config() -> dict:
    sub2 = get_sub2api_config()
    return {
        "url": sub2["url"],
        "email": sub2.get("admin_email") or "",
        "password": sub2.get("admin_password") or "",
    }


def get_sub2api_config_from_cfg(cfg: dict) -> dict:
    url = normalize_upstream_url(
        cfg.get("SUB2API_URL")
        or cfg.get("UPSTREAM_URL")
        or DEFAULTS["SUB2API_URL"]
    )
    return {
        "url": url,
        "container": (cfg.get("SUB2API_DOCKER_CONTAINER") or DEFAULTS["SUB2API_DOCKER_CONTAINER"]).strip(),
        "db_host": (cfg.get("SUB2API_DB_HOST") or DEFAULTS["SUB2API_DB_HOST"]).strip(),
        "db_port": (cfg.get("SUB2API_DB_PORT") or DEFAULTS["SUB2API_DB_PORT"]).strip(),
        "db_name": (cfg.get("SUB2API_DB_NAME") or DEFAULTS["SUB2API_DB_NAME"]).strip(),
        "db_user": (cfg.get("SUB2API_DB_USER") or DEFAULTS["SUB2API_DB_USER"]).strip(),
        "db_password": (cfg.get("SUB2API_DB_PASSWORD") or DEFAULTS["SUB2API_DB_PASSWORD"]).strip(),
        "group_id": (cfg.get("SUB2API_GROK_GROUP_ID") or DEFAULTS["SUB2API_GROK_GROUP_ID"]).strip(),
        "group_name": (cfg.get("SUB2API_GROK_GROUP_NAME") or DEFAULTS["SUB2API_GROK_GROUP_NAME"]).strip(),
        "admin_email": (cfg.get("UPSTREAM_ADMIN_EMAIL") or "").strip(),
        "admin_password": (cfg.get("UPSTREAM_ADMIN_PASSWORD") or "").strip(),
    }


def get_sub2api_config() -> dict:
    return get_sub2api_config_from_cfg(read_env_file())


def sub2api_list_groups(
    *,
    token: str,
    base_url: str,
    platform: str | None = None,
    page_size: int = 100,
) -> dict:
    """拉取 sub2api 分组列表。platform 为空则拉全部分组（便于按名称随意指定）。"""
    params: dict = {
        "page": 1,
        "page_size": max(1, min(int(page_size or 100), 200)),
    }
    plat = str(platform or "").strip()
    if plat:
        params["platform"] = plat
    groups_resp = sub2api_http_request(
        "GET",
        "/api/v1/admin/groups",
        token=token,
        base_url=base_url,
        params=params,
        timeout=15,
    )
    if not groups_resp.get("ok"):
        return {
            "ok": False,
            "error": groups_resp.get("error") or "读取分组失败",
            "items": [],
            "status_code": groups_resp.get("status_code"),
        }
    data = groups_resp.get("data") or {}
    items = data.get("items") if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = []
    cleaned = [it for it in items if isinstance(it, dict)]
    return {"ok": True, "items": cleaned, "raw": data}


def sub2api_list_grok_groups(
    *,
    token: str,
    base_url: str,
    page_size: int = 100,
) -> dict:
    """兼容旧调用：默认拉全部分组（不再锁死 platform=grok）。"""
    return sub2api_list_groups(
        token=token,
        base_url=base_url,
        platform=None,
        page_size=page_size,
    )


def _group_preview_text(items: list[dict], limit: int = 12) -> str:
    preview = []
    for it in (items or [])[: max(1, limit)]:
        if not isinstance(it, dict) or it.get("id") is None:
            continue
        name = str(it.get("name") or "").strip() or "?"
        plat = str(it.get("platform") or "").strip()
        if plat:
            preview.append(f"{name}({it.get('id')}/{plat})")
        else:
            preview.append(f"{name}({it.get('id')})")
    return ", ".join(preview)


def resolve_sub2api_group(
    *,
    token: str,
    base_url: str,
    group_name: str | None = None,
    group_id: str | int | None = None,
    persist: bool = False,
    prefer_platform: str | None = "grok",
) -> dict:
    """
    按分组名称解析 group_id（名称优先；可指定任意已存在分组，不限 grok）。
    同名多条时优先 prefer_platform（默认 grok），再精确名、再唯一模糊。
    命中后可把解析到的 ID 写回 .env。
    """
    want_name = str(group_name or "").strip()
    want_id_raw = str(group_id or "").strip()
    want_id = None
    if want_id_raw.isdigit():
        want_id = int(want_id_raw)
    prefer = str(prefer_platform or "").strip().lower()

    listed = sub2api_list_groups(token=token, base_url=base_url, platform=None)
    if not listed.get("ok"):
        return {
            "ok": False,
            "error": listed.get("error") or "读取分组失败",
            "items": [],
            "status_code": listed.get("status_code"),
        }
    items = listed.get("items") or []

    matched = None
    match_by = ""
    if want_name:
        want_l = want_name.lower()
        exact = [
            it for it in items
            if str(it.get("name") or "").strip().lower() == want_l
        ]
        if len(exact) == 1:
            matched = exact[0]
            match_by = "name"
        elif len(exact) > 1:
            # 同名多平台：优先 prefer_platform
            if prefer:
                preferred = [
                    it for it in exact
                    if str(it.get("platform") or "").strip().lower() == prefer
                ]
                if preferred:
                    matched = preferred[0]
                    match_by = f"name+{prefer}"
            if matched is None:
                matched = exact[0]
                match_by = "name_multi"
        # 包含匹配（仅唯一命中时接受）
        if matched is None:
            fuzzy = [
                it for it in items
                if want_l in str(it.get("name") or "").strip().lower()
            ]
            if len(fuzzy) == 1:
                matched = fuzzy[0]
                match_by = "name_fuzzy"
            elif len(fuzzy) > 1 and prefer:
                preferred = [
                    it for it in fuzzy
                    if str(it.get("platform") or "").strip().lower() == prefer
                ]
                if len(preferred) == 1:
                    matched = preferred[0]
                    match_by = f"name_fuzzy+{prefer}"
        # 填了名称就必须按名称命中，禁止回退到旧 ID
    elif want_id is not None:
        for it in items:
            try:
                if int(it.get("id") or 0) == want_id:
                    matched = it
                    match_by = "id"
                    break
            except (TypeError, ValueError):
                continue

    if matched is None:
        preview = _group_preview_text(items, 12)
        hint = f"可选: {preview}" if preview else "当前无任何分组"
        target = want_name or (f"id={want_id}" if want_id is not None else "(未指定)")
        return {
            "ok": False,
            "error": (
                f"sub2api 分组未匹配: {target}。{hint}。"
                "名称必须是 sub2api 里已有的分组（可任意平台）；新分组请先在 sub2api 后台创建。"
            ),
            "items": items,
            "group_name": want_name,
            "group_id": want_id,
        }

    try:
        gid = int(matched.get("id"))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": f"分组 ID 非法: {matched.get('id')}",
            "items": items,
        }
    gname = str(matched.get("name") or want_name or "").strip() or str(gid)
    gplat = str(matched.get("platform") or "").strip()

    if persist:
        try:
            cfg = read_env_file()
            cfg["SUB2API_GROK_GROUP_ID"] = str(gid)
            cfg["SUB2API_GROK_GROUP_NAME"] = gname
            write_env_file(cfg)
            apply_env_to_process({
                "SUB2API_GROK_GROUP_ID": str(gid),
                "SUB2API_GROK_GROUP_NAME": gname,
            })
        except Exception:
            # 解析成功即可用；写回失败不阻断导入
            pass

    return {
        "ok": True,
        "group_id": gid,
        "group_name": gname,
        "platform": gplat,
        "match_by": match_by,
        "group": matched,
        "items": items,
    }


def _rfc3339_seconds(value) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        if re.fullmatch(r"\d+(\.\d+)?", raw):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        s = raw.replace("Z", "+00:00")
        if "." in s:
            head, tail = s.split(".", 1)
            tz = ""
            for marker in ("+", "-"):
                pos = tail.find(marker)
                if pos > 0:
                    tz = tail[pos:]
                    tail = tail[:pos]
                    break
            s = head + "." + tail[:6].ljust(6, "0") + tz
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw


def _entry_to_sub2api_credentials(entry: dict, email_hint: str = "") -> tuple[dict, str, str, str, str]:
    from grok import decode_jwt_payload

    access = (entry or {}).get("access_token") or (entry or {}).get("key") or ""
    refresh = (entry or {}).get("refresh_token") or ""
    payload = decode_jwt_payload(access)
    issuer = (entry or {}).get("oidc_issuer") or payload.get("iss") or "https://auth.x.ai"
    client_id = (
        (entry or {}).get("client_id")
        or (entry or {}).get("oidc_client_id")
        or payload.get("client_id")
        or payload.get("aud")
        or "b1a00492-073a-47ea-816f-4c329264a828"
    )
    user_id = (entry or {}).get("user_id") or payload.get("sub") or payload.get("principal_id") or ""
    principal_id = (entry or {}).get("principal_id") or payload.get("principal_id") or user_id
    principal_type = (entry or {}).get("principal_type") or payload.get("principal_type") or "User"
    email = (email_hint or (entry or {}).get("email") or payload.get("email") or "").strip()
    expires_at = _rfc3339_seconds((entry or {}).get("expires_at") or payload.get("exp") or "")
    auth_key = (entry or {}).get("auth_key") or (f"{issuer}::{user_id}" if user_id else "")
    credentials = {
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "base_url": (entry or {}).get("base_url") or "https://cli-chat-proxy.grok.com/v1",
        "auth_key": auth_key,
        "user_id": user_id,
        "auth_mode": (entry or {}).get("auth_mode") or "oidc",
        "client_id": client_id,
        "oidc_issuer": issuer,
        "email": email,
        "token_type": (entry or {}).get("token_type") or "Bearer",
        "principal_id": principal_id,
        "principal_type": principal_type,
    }
    if payload.get("scope"):
        credentials["scope"] = payload.get("scope")
    if payload.get("team_id"):
        credentials["team_id"] = payload.get("team_id")
    if payload.get("sub"):
        credentials["sub"] = payload.get("sub")
    name = email or (f"Grok {user_id}" if user_id else "Grok OAuth")
    return credentials, name, auth_key, user_id, email


def _http_session():
    """本机/局域网上游请求禁用系统代理，避免 7897 之类代理把内网请求拖死。"""
    import requests

    s = requests.Session()
    s.trust_env = False
    return s


def _sub2api_api_data(resp_json) -> dict | list | None:
    """解析 sub2api 统一响应 {code, message, data}。"""
    if not isinstance(resp_json, dict):
        return None
    if "data" in resp_json:
        return resp_json.get("data")
    return resp_json


def _sub2api_api_ok(status_code: int, resp_json) -> bool:
    if status_code < 200 or status_code >= 300:
        return False
    if isinstance(resp_json, dict) and "code" in resp_json:
        try:
            return int(resp_json.get("code")) == 0
        except (TypeError, ValueError):
            return False
    return True


def _sub2api_api_message(resp_json, fallback: str = "") -> str:
    if isinstance(resp_json, dict):
        msg = resp_json.get("message") or resp_json.get("error") or ""
        if msg:
            return str(msg)
        data = resp_json.get("data")
        if isinstance(data, dict) and data.get("message"):
            return str(data["message"])
    return fallback or "unknown error"


def sub2api_http_login(
    base_url: str | None = None,
    email: str | None = None,
    password: str | None = None,
    cfg: dict | None = None,
) -> dict:
    """管理员登录，拿 Bearer access_token。"""
    import requests

    cfg = dict(cfg or get_sub2api_config())
    base = normalize_upstream_url(base_url if base_url is not None else cfg.get("url"))
    admin_email = (email if email is not None else cfg.get("admin_email") or "").strip()
    admin_password = password if password is not None else (cfg.get("admin_password") or "")
    if not base:
        return {"ok": False, "error": "请先填写 SUB2API_URL"}
    if not admin_email or not admin_password:
        return {"ok": False, "error": "请先填写 UPSTREAM_ADMIN_EMAIL / UPSTREAM_ADMIN_PASSWORD"}

    try:
        r = _http_session().post(
            f"{base}/api/v1/auth/login",
            json={"email": admin_email, "password": admin_password},
            timeout=12,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            body = r.json()
        except Exception:
            body = {"raw": (r.text or "")[:300]}
        if not _sub2api_api_ok(r.status_code, body):
            return {
                "ok": False,
                "error": f"登录失败 HTTP {r.status_code}: {_sub2api_api_message(body, r.text[:200])}",
                "status_code": r.status_code,
                "base_url": base,
            }
        data = _sub2api_api_data(body) or {}
        if not isinstance(data, dict):
            data = {}
        token = (
            data.get("access_token")
            or data.get("token")
            or body.get("access_token")
            or body.get("token")
            or ""
        )
        if not token:
            return {"ok": False, "error": "登录成功但未返回 access_token", "base_url": base}
        return {
            "ok": True,
            "access_token": token,
            "refresh_token": data.get("refresh_token") or "",
            "base_url": base,
            "email": admin_email,
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": f"连接 sub2api 失败: {base}", "base_url": base}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": f"登录超时: {base}", "base_url": base}
    except Exception as e:
        return {"ok": False, "error": f"登录异常: {e}", "base_url": base}


def sub2api_http_request(
    method: str,
    path: str,
    *,
    token: str,
    base_url: str,
    json_body: dict | list | None = None,
    params: dict | None = None,
    timeout: float = 30.0,
) -> dict:
    """带 Bearer 的 sub2api Admin API 请求。"""
    import requests

    base = normalize_upstream_url(base_url)
    if not base:
        return {"ok": False, "error": "缺少 base_url"}
    if not path.startswith("/"):
        path = "/" + path
    url = f"{base}{path}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        r = _http_session().request(
            method.upper(),
            url,
            headers=headers,
            json=json_body,
            params=params,
            timeout=timeout,
        )
        try:
            body = r.json()
        except Exception:
            body = {"raw": (r.text or "")[:500]}
        ok = _sub2api_api_ok(r.status_code, body)
        return {
            "ok": ok,
            "status_code": r.status_code,
            "body": body,
            "data": _sub2api_api_data(body),
            "error": None if ok else _sub2api_api_message(body, f"HTTP {r.status_code}"),
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": f"连接失败: {url}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": f"请求超时: {url}"}
    except Exception as e:
        return {"ok": False, "error": f"请求异常: {e}"}


def sub2api_find_account(
    token: str,
    base_url: str,
    *,
    email: str = "",
    user_id: str = "",
    auth_key: str = "",
    name: str = "",
) -> dict | None:
    """按 email / user_id / auth_key 在 grok 账号里找已有记录。"""
    keywords: list[str] = []
    for k in (email, user_id, name, (auth_key.split("::")[-1] if auth_key else "")):
        k = (k or "").strip()
        if k and k not in keywords:
            keywords.append(k)
    if not keywords:
        return None

    for kw in keywords[:3]:
        resp = sub2api_http_request(
            "GET",
            "/api/v1/admin/accounts",
            token=token,
            base_url=base_url,
            params={
                "page": 1,
                "page_size": 20,
                "platform": "grok",
                "keyword": kw,
            },
            timeout=15,
        )
        if not resp.get("ok"):
            continue
        data = resp.get("data") or {}
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            continue
        email_l = (email or "").strip().lower()
        for it in items:
            if not isinstance(it, dict):
                continue
            cred = it.get("credentials") or {}
            if not isinstance(cred, dict):
                cred = {}
            it_email = (cred.get("email") or it.get("name") or "").strip().lower()
            it_uid = str(cred.get("user_id") or cred.get("sub") or "").strip()
            it_ak = str(cred.get("auth_key") or "").strip()
            if email_l and it_email == email_l:
                return it
            if user_id and it_uid and it_uid == user_id:
                return it
            if auth_key and it_ak and it_ak == auth_key:
                return it
            if name and (it.get("name") or "") == name:
                return it
    return None


def sub2api_import_auth_entry(
    entry: dict,
    email_hint: str = "",
    merge: bool = True,
    *,
    token: str | None = None,
    base_url: str | None = None,
    cfg: dict | None = None,
) -> dict:
    """通过 HTTP Admin API 写入/更新 grok oauth 账号。"""
    cfg = dict(cfg or get_sub2api_config())
    base = normalize_upstream_url(base_url or cfg.get("url"))
    credentials, name, auth_key, user_id, email = _entry_to_sub2api_credentials(entry, email_hint)

    if not token:
        login = sub2api_http_login(base_url=base, cfg=cfg)
        if not login.get("ok"):
            return {
                "ok": False,
                "error": login.get("error") or "sub2api 登录失败",
                "email": email or None,
                "user_id": user_id or None,
            }
        token = login["access_token"]
        base = login.get("base_url") or base

    # 优先按分组名称解析 ID；已有数字 ID 仅作兜底
    resolved = resolve_sub2api_group(
        token=token,
        base_url=base,
        group_name=cfg.get("group_name"),
        group_id=cfg.get("group_id"),
        persist=False,
    )
    if not resolved.get("ok"):
        return {
            "ok": False,
            "error": resolved.get("error") or "分组解析失败",
            "email": email or None,
            "user_id": user_id or None,
        }
    group_id = int(resolved["group_id"])
    cfg["group_id"] = str(group_id)
    if resolved.get("group_name"):
        cfg["group_name"] = str(resolved["group_name"])

    existing = sub2api_find_account(
        token,
        base,
        email=email,
        user_id=user_id,
        auth_key=auth_key,
        name=name,
    )

    payload = {
        "name": name,
        "platform": "grok",
        "type": "oauth",
        "group_ids": [group_id],
        "concurrency": 1,
        "priority": 50,
        "rate_multiplier": 1.0,
        "auto_pause_on_expired": True,
        "status": "active",
        "schedulable": True,
        "credentials": credentials,
    }

    if existing and existing.get("id") is not None:
        if not merge:
            return {
                "ok": False,
                "error": "sub2api 已存在相同账号",
                "email": email or None,
                "user_id": user_id or None,
                "id": existing.get("id"),
                "duplicate": True,
            }
        account_id = existing["id"]
        # 保留已有分组，确保目标 group 在列表里
        old_gids = existing.get("group_ids") or []
        if isinstance(old_gids, list):
            gids = []
            for g in old_gids:
                try:
                    gids.append(int(g))
                except (TypeError, ValueError):
                    pass
            if group_id not in gids:
                gids.append(group_id)
            if gids:
                payload["group_ids"] = gids
        resp = sub2api_http_request(
            "PUT",
            f"/api/v1/admin/accounts/{account_id}",
            token=token,
            base_url=base,
            json_body=payload,
            timeout=30,
        )
        if not resp.get("ok"):
            return {
                "ok": False,
                "error": resp.get("error") or "更新账号失败",
                "email": email or None,
                "user_id": user_id or None,
            }
        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        return {
            "ok": True,
            "id": data.get("id") or account_id,
            "action": "updated",
            "group_id": group_id,
            "email": email or None,
            "user_id": user_id or None,
            "auth_key": auth_key,
            "expires_at": credentials.get("expires_at") or "",
            "has_refresh_token": bool(credentials.get("refresh_token")),
        }

    resp = sub2api_http_request(
        "POST",
        "/api/v1/admin/accounts",
        token=token,
        base_url=base,
        json_body=payload,
        timeout=30,
    )
    if not resp.get("ok"):
        return {
            "ok": False,
            "error": resp.get("error") or "创建账号失败",
            "email": email or None,
            "user_id": user_id or None,
        }
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    return {
        "ok": True,
        "id": data.get("id"),
        "action": "inserted",
        "group_id": group_id,
        "email": email or None,
        "user_id": user_id or None,
        "auth_key": auth_key,
        "expires_at": credentials.get("expires_at") or "",
        "has_refresh_token": bool(credentials.get("refresh_token")),
    }


def sub2api_import_sso_tokens_http(
    sso_tokens: list[str],
    *,
    token: str,
    base_url: str,
    group_id: int,
    emails: list[str] | None = None,
) -> dict:
    """
    调用 sub2api 服务端 sso-to-oauth：
    POST /api/v1/admin/grok/sso-to-oauth
    body: {sso_tokens, group_ids}
    返回 data: {created: [...], failed: [{index, error}, ...]}
    """
    tokens = [str(t).strip() for t in (sso_tokens or []) if str(t).strip()]
    if not tokens:
        return {"ok": False, "error": "sso_tokens 为空", "created": [], "failed": []}

    body: dict = {
        "sso_tokens": tokens,
        "group_ids": [int(group_id)],
        "auto_pause_on_expired": True,
    }
    # 部分版本支持 name；不强制
    if emails and len(emails) == 1 and emails[0]:
        body["name"] = emails[0]

    resp = sub2api_http_request(
        "POST",
        "/api/v1/admin/grok/sso-to-oauth",
        token=token,
        base_url=base_url,
        json_body=body,
        # 批量换票较慢：默认 5 分钟；可用 SUB2API_SSO_TIMEOUT 覆盖
        timeout=float(os.environ.get("SUB2API_SSO_TIMEOUT") or 300),
    )
    if not resp.get("ok"):
        return {
            "ok": False,
            "error": resp.get("error") or "sso-to-oauth 失败",
            "created": [],
            "failed": [{"index": i + 1, "error": resp.get("error") or "request failed"} for i in range(len(tokens))],
            "status_code": resp.get("status_code"),
        }
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    created_raw = data.get("created") if isinstance(data.get("created"), list) else []
    failed = data.get("failed") if isinstance(data.get("failed"), list) else []
    # 服务端结构：{index, name, email, account:{id, credentials, ...}}
    # 展平 account，方便上层直接取 id / credentials
    created: list[dict] = []
    for c in created_raw:
        if not isinstance(c, dict):
            continue
        acc = c.get("account") if isinstance(c.get("account"), dict) else {}
        flat = dict(c)
        if acc:
            # 顶层优先保留 index/name/email；id/credentials 从 account 补
            if flat.get("id") is None and acc.get("id") is not None:
                flat["id"] = acc.get("id")
            if not isinstance(flat.get("credentials"), dict) and isinstance(
                acc.get("credentials"), dict
            ):
                flat["credentials"] = acc.get("credentials")
            for k in ("user_id", "expires_at", "status", "platform", "type"):
                if flat.get(k) is None and acc.get(k) is not None:
                    flat[k] = acc.get(k)
            if not flat.get("email"):
                cred = acc.get("credentials") if isinstance(acc.get("credentials"), dict) else {}
                flat["email"] = (
                    c.get("email")
                    or acc.get("name")
                    or cred.get("email")
                    or c.get("name")
                )
            flat["_account"] = acc
        created.append(flat)
    return {
        "ok": True,
        "created": created,
        "failed": failed,
        "raw": data,
    }


def test_upstream_connectivity(
    base_url: str | None = None,
    password: str | None = None,
    email: str | None = None,
    group_id: str | int | None = None,
    group_name: str | None = None,
) -> dict:
    """验证 sub2api HTTP 登录，并按分组名称自动解析 group_id。"""
    import requests

    cfg = get_sub2api_config()
    base = normalize_upstream_url(base_url if base_url is not None else cfg["url"])
    admin_email = (email if email is not None else cfg.get("admin_email") or "").strip()
    admin_password = password if password is not None else (cfg.get("admin_password") or "")
    if base:
        cfg["url"] = base
    if admin_email:
        cfg["admin_email"] = admin_email
    if admin_password is not None and str(admin_password) != "":
        cfg["admin_password"] = admin_password
    if group_id is not None and str(group_id).strip() != "":
        cfg["group_id"] = str(group_id).strip()
    if group_name is not None and str(group_name).strip() != "":
        cfg["group_name"] = str(group_name).strip()

    if not base:
        return {"ok": False, "message": "请先填写 SUB2API_URL"}
    if not cfg.get("admin_email") or not cfg.get("admin_password"):
        return {"ok": False, "message": "请先填写管理员邮箱与密码（UPSTREAM_ADMIN_EMAIL / PASSWORD）", "base_url": base}
    if not str(cfg.get("group_name") or "").strip():
        return {"ok": False, "message": "请先填写分组名称（SUB2API_GROK_GROUP_NAME）", "base_url": base}

    health = None
    try:
        hr = _http_session().get(f"{base}/health", timeout=6)
        if hr.status_code == 200:
            try:
                health = hr.json()
            except Exception:
                health = {"raw": hr.text[:200]}
        else:
            return {
                "ok": False,
                "message": f"sub2api 健康检查 HTTP {hr.status_code}",
                "base_url": base,
                "health_status": hr.status_code,
            }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": f"连接 sub2api 失败: {base}", "base_url": base}
    except requests.exceptions.Timeout:
        return {"ok": False, "message": f"sub2api 健康检查超时: {base}", "base_url": base}
    except Exception as e:
        return {"ok": False, "message": f"sub2api 健康检查异常: {e}", "base_url": base}

    login = sub2api_http_login(base_url=base, email=cfg.get("admin_email"), password=cfg.get("admin_password"), cfg=cfg)
    if not login.get("ok"):
        return {
            "ok": False,
            "message": login.get("error") or "管理员登录失败",
            "base_url": base,
            "health": health,
            "health_ok": True,
            "login_ok": False,
        }

    token = login["access_token"]
    resolved = resolve_sub2api_group(
        token=token,
        base_url=base or login.get("base_url") or "",
        group_name=cfg.get("group_name"),
        group_id=cfg.get("group_id"),
        persist=True,
    )
    if not resolved.get("ok"):
        return {
            "ok": False,
            "message": resolved.get("error") or "分组解析失败",
            "base_url": base,
            "health": health,
            "health_ok": True,
            "login_ok": True,
            "groups": [
                {"id": it.get("id"), "name": it.get("name")}
                for it in (resolved.get("items") or [])[:20]
            ],
        }

    gname = resolved.get("group_name") or cfg.get("group_name")
    gid = resolved.get("group_id")
    group = resolved.get("group") or {}
    gplat = resolved.get("platform") or group.get("platform") or ""
    return {
        "ok": True,
        "message": (
            f"sub2api HTTP 连通正常，分组 {gname} → id={gid}"
            + (f"/{gplat}" if gplat else "")
            + "（按名称自动解析）"
        ),
        "base_url": base,
        "health": health,
        "health_ok": True,
        "login_ok": True,
        "http_ok": True,
        "group": {
            "group_id": gid,
            "group_name": gname,
            "platform": gplat,
            "status": group.get("status"),
            "match_by": resolved.get("match_by"),
        },
        "groups": [
            {"id": it.get("id"), "name": it.get("name"), "platform": it.get("platform")}
            for it in (resolved.get("items") or [])[:30]
        ],
    }


def _parse_sso_import_lines(sso_lines: list[str]) -> list[tuple[str, str]]:
    """解析 email----sso / 纯 sso 行，返回 [(email, sso), ...]。"""
    out: list[tuple[str, str]] = []
    for raw in sso_lines or []:
        for line in str(raw or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            email = ""
            sso = line
            if "----" in line:
                parts = line.split("----")
                email = parts[0].strip()
                sso = parts[-1].strip()
            elif ":" in line and not line.startswith("eyJ"):
                parts = line.rsplit(":", 1)
                email = parts[0].strip()
                sso = parts[-1].strip()
            if sso:
                out.append((email, sso))
    return out


def _normalize_import_accounts(
    sso_lines: list[str] | None = None,
    accounts: list[dict] | None = None,
) -> list[dict]:
    """
    统一导入入参：
    - accounts: [{email?, sso, auth_token?}, ...]（注册成功缓存 token 的首选路径）
    - sso_lines: email----sso / 纯 sso（无 token，需 device flow）
    """
    out: list[dict] = []
    seen_sso: set[str] = set()

    if accounts:
        for raw in accounts:
            if not isinstance(raw, dict):
                continue
            sso = str(raw.get("sso") or "").strip()
            if not sso or sso in seen_sso:
                continue
            seen_sso.add(sso)
            email = str(raw.get("email") or "").strip()
            token = raw.get("auth_token")
            out.append(
                {
                    "email": email,
                    "sso": sso,
                    "auth_token": token if isinstance(token, dict) else None,
                }
            )

    if sso_lines:
        for email, sso in _parse_sso_import_lines(sso_lines):
            sso = (sso or "").strip()
            if not sso or sso in seen_sso:
                continue
            seen_sso.add(sso)
            out.append(
                {
                    "email": (email or "").strip(),
                    "sso": sso,
                    "auth_token": None,
                }
            )
    return out


def import_sso_to_upstream(
    sso_lines: list[str] | None = None,
    merge: bool = True,
    max_workers: int = 1,
    base_url: str | None = None,
    password: str | None = None,
    email: str | None = None,
    accounts: list[dict] | None = None,
) -> dict:
    """
    导入 SSO 到 sub2api 的 grok 分组（HTTP Admin API）。

    流程：
    1) 有缓存 auth_token（注册流水线 risk 后前台换票）→ HTTP 直写 accounts
    2) 无缓存 → 服务端 /api/v1/admin/grok/sso-to-oauth
    3) sso-to-oauth 失败且可重试 → 本机 device flow 仅作兜底，再 HTTP 写 accounts
    """
    import time
    from grok import (
        sso_device_flow_to_token,
        token_to_auth_entry,
        is_auth_token_usable,
        append_token_record,
        _device_flow_error_kind,
        _device_flow_wait_seconds,
        _mark_device_flow_cooldown,
    )

    del max_workers  # 保留参数兼容；HTTP 写串行更稳
    if base_url:
        os.environ["SUB2API_URL"] = normalize_upstream_url(base_url)
    sub2 = get_sub2api_config()
    if email is not None and str(email).strip():
        sub2["admin_email"] = str(email).strip()
    if password is not None and str(password) != "":
        sub2["admin_password"] = str(password)

    items = _normalize_import_accounts(sso_lines=sso_lines, accounts=accounts)
    if not items:
        return {"ok": False, "message": "没有可导入的 SSO"}
    if not sub2.get("url"):
        return {"ok": False, "message": "请先配置 SUB2API_URL"}
    if not str(sub2.get("group_name") or "").strip():
        return {"ok": False, "message": "请先配置分组名称（SUB2API_GROK_GROUP_NAME）"}
    if not sub2.get("admin_email") or not sub2.get("admin_password"):
        return {"ok": False, "message": "请先配置管理员邮箱与密码（UPSTREAM_ADMIN_EMAIL / PASSWORD）"}

    login = sub2api_http_login(cfg=sub2)
    if not login.get("ok"):
        return {
            "ok": False,
            "message": login.get("error") or "sub2api 管理员登录失败",
            "base_url": sub2.get("url"),
        }
    api_token = login["access_token"]
    api_base = login.get("base_url") or sub2.get("url")

    resolved = resolve_sub2api_group(
        token=api_token,
        base_url=api_base,
        group_name=sub2.get("group_name"),
        group_id=sub2.get("group_id"),
        persist=True,
    )
    if not resolved.get("ok"):
        return {
            "ok": False,
            "message": resolved.get("error") or "分组名称未能解析到 ID",
            "base_url": api_base,
            "group_name": sub2.get("group_name"),
        }
    group_id = int(resolved["group_id"])
    sub2["group_id"] = str(group_id)
    if resolved.get("group_name"):
        sub2["group_name"] = str(resolved["group_name"])
    gplat = resolved.get("platform") or ""
    logs.emit(
        f"sub2api 分组解析: {sub2.get('group_name')} → id={group_id}"
        + (f"/{gplat}" if gplat else "")
        + f"（by {resolved.get('match_by') or 'name'}）",
        "info",
    )
    if gplat and gplat.lower() != "grok":
        logs.emit(
            f"提示：目标分组 platform={gplat}（非 grok）。Grok 账号仍可写入该 group_ids，"
            "若 sub2api 侧有平台校验失败再换回 grok 分组。",
            "warn",
        )

    results_by_idx: dict[int, dict] = {}
    imported: list[dict] = []
    ok_count = 0
    fail_count = 0
    cached_hits = 0
    flow_hits = 0
    sso_api_hits = 0

    def _write_token_to_sub2api(entry: dict, email_hint: str, idx: int) -> dict:
        item: dict = {
            "index": idx,
            "email": email_hint or None,
            "sso_hint": None,
        }
        data = sub2api_import_auth_entry(
            entry,
            email_hint=email_hint,
            merge=merge,
            token=api_token,
            base_url=api_base,
            cfg=sub2,
        )
        if not data.get("ok"):
            item["status"] = "failed"
            item["error"] = data.get("error") or "sub2api 写入失败"
            item["email"] = data.get("email") or email_hint or None
            item["user_id"] = data.get("user_id") or entry.get("user_id")
            return item

        item["status"] = "ok"
        item["account_id"] = data.get("id")
        item["action"] = data.get("action")
        item["group_id"] = data.get("group_id")
        item["email"] = data.get("email") or email_hint or entry.get("email") or None
        item["user_id"] = data.get("user_id") or entry.get("user_id")
        item["expires_at"] = data.get("expires_at") or entry.get("expires_at")
        item["has_refresh_token"] = bool(
            data.get("has_refresh_token")
            if "has_refresh_token" in data
            else entry.get("refresh_token")
        )
        return item

    def _device_flow_to_token(sso: str, idx: int, *, pass_label: str, max_attempts: int):
        flow = None
        last_flow_err = "本机 device flow 失败"
        for attempt in range(1, max_attempts + 1):
            # 导入必须真正换票；覆盖全局诊断开关 GROK_DEVICE_FLOW_ISSUE_TOKEN=0
            flow = sso_device_flow_to_token(sso, timeout=28, issue_token=True)
            if flow.get("ok") and flow.get("token"):
                return flow, None
            if flow.get("ok") and not flow.get("token"):
                last_flow_err = flow.get("note") or "device approve 成功但未下发 token"
            else:
                last_flow_err = flow.get("error") or last_flow_err
            if "会话无效" in str(last_flow_err) or "非有效 JWT" in str(last_flow_err):
                break
            kind = _device_flow_error_kind(str(last_flow_err))
            if attempt < max_attempts:
                wait = _device_flow_wait_seconds(str(last_flow_err), attempt)
                if kind == "rate_limited":
                    _mark_device_flow_cooldown(wait)
                logs.emit(
                    f"sub2api 导入{pass_label} [{idx}/{len(items)}] device flow 重试 "
                    f"{attempt}/{max_attempts}（{kind}: {last_flow_err}），等待 {wait:.0f}s…",
                    "warn",
                )
                time.sleep(wait)
        return None, last_flow_err

    def _mark_ok(item: dict) -> None:
        nonlocal ok_count
        ok_count += 1
        imported.append(
            {
                "id": item.get("account_id"),
                "email": item.get("email"),
                "user_id": item.get("user_id"),
                "expires_at": item.get("expires_at"),
                "has_refresh_token": item.get("has_refresh_token"),
            }
        )

    # —— 路径 A：有缓存 token（注册时 CLEAN 后已换票）→ HTTP 直写 accounts ——
    need_sso_indices: list[int] = []
    cached_ready = sum(1 for it in items if is_auth_token_usable(it.get("auth_token")))
    if cached_ready:
        logs.emit(
            f"sub2api 导入：{len(items)} 条中 {cached_ready} 条已有注册缓存 token，优先直写（不换票）",
            "info",
        )
    elif items:
        logs.emit(
            f"sub2api 导入：{len(items)} 条无可用缓存 token，走 sso-to-oauth；本机换票仅兜底",
            "info",
        )

    for idx, acc in enumerate(items, 1):
        email_hint = acc.get("email") or ""
        sso = acc.get("sso") or ""
        auth_token = acc.get("auth_token") if isinstance(acc.get("auth_token"), dict) else None
        sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso

        if is_auth_token_usable(auth_token):
            try:
                entry = token_to_auth_entry(auth_token, email=email_hint or "")
                item = _write_token_to_sub2api(entry, email_hint or "", idx)
                item["sso_hint"] = sso_hint
                item["via"] = "cached_token_http"
                if item.get("status") == "ok":
                    cached_hits += 1
                    _mark_ok(item)
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 成功(cached_token_http): "
                        f"{item.get('email') or item.get('user_id') or 'ok'}",
                        "success",
                    )
                else:
                    fail_count += 1
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 失败(cached_token_http): {item.get('error')}",
                        "warn",
                    )
                results_by_idx[idx] = item
            except Exception as e:
                fail_count += 1
                item = {
                    "index": idx,
                    "email": email_hint or None,
                    "sso_hint": sso_hint,
                    "status": "failed",
                    "error": f"导入异常: {e}",
                    "retryable": True,
                    "via": "error",
                }
                results_by_idx[idx] = item
                logs.emit(f"sub2api 导入 [{idx}/{len(items)}] 异常: {e}", "error")
        else:
            need_sso_indices.append(idx)

    # —— 路径 B：无缓存 → 服务端 sso-to-oauth（批量，服务端自己换票） ——
    if need_sso_indices:
        sso_list = [items[i - 1].get("sso") or "" for i in need_sso_indices]
        email_list = [items[i - 1].get("email") or "" for i in need_sso_indices]
        logs.emit(
            f"sub2api HTTP 导入：{len(need_sso_indices)} 条走服务端 sso-to-oauth…",
            "info",
        )
        # 分批，避免一次塞太多
        batch_size = 20
        for batch_start in range(0, len(need_sso_indices), batch_size):
            batch_idxs = need_sso_indices[batch_start : batch_start + batch_size]
            batch_tokens = [items[i - 1].get("sso") or "" for i in batch_idxs]
            batch_emails = [items[i - 1].get("email") or "" for i in batch_idxs]
            api_result = sub2api_import_sso_tokens_http(
                batch_tokens,
                token=api_token,
                base_url=api_base,
                group_id=group_id,
                emails=batch_emails if len(batch_emails) == 1 else None,
            )

            # 建立 index(1-based in batch) -> result
            created_by_index: dict[int, dict] = {}
            failed_by_index: dict[int, str] = {}
            if api_result.get("ok"):
                for c in api_result.get("created") or []:
                    if not isinstance(c, dict):
                        continue
                    # created 可能是账号对象或 {index, ...}
                    ci = c.get("index")
                    if ci is None and c.get("id") is not None:
                        # 无 index 时按顺序不好对齐，先跳过 index 映射，后面按失败列表补
                        pass
                    if ci is not None:
                        try:
                            created_by_index[int(ci)] = c
                        except (TypeError, ValueError):
                            pass
                # 若 created 无 index 字段，按返回顺序对齐成功数
                if not created_by_index and api_result.get("created"):
                    created_list = [c for c in api_result["created"] if isinstance(c, dict)]
                    failed_set = set()
                    for f in api_result.get("failed") or []:
                        if isinstance(f, dict) and f.get("index") is not None:
                            try:
                                failed_set.add(int(f["index"]))
                            except (TypeError, ValueError):
                                pass
                    # 1-based batch positions not in failed → success in order
                    success_slots = [i for i in range(1, len(batch_idxs) + 1) if i not in failed_set]
                    for slot, c in zip(success_slots, created_list):
                        created_by_index[slot] = c

                for f in api_result.get("failed") or []:
                    if not isinstance(f, dict):
                        continue
                    fi = f.get("index")
                    if fi is None:
                        continue
                    try:
                        failed_by_index[int(fi)] = str(f.get("error") or "sso-to-oauth failed")
                    except (TypeError, ValueError):
                        pass
            else:
                # 整批失败：全部标记，后面可走 device flow 兜底
                err = api_result.get("error") or "sso-to-oauth 请求失败"
                for bi, idx in enumerate(batch_idxs, 1):
                    failed_by_index[bi] = err

            for bi, idx in enumerate(batch_idxs, 1):
                email_hint = items[idx - 1].get("email") or ""
                sso = items[idx - 1].get("sso") or ""
                sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso
                if bi in created_by_index:
                    c = created_by_index[bi]
                    acc = c.get("account") if isinstance(c.get("account"), dict) else (
                        c.get("_account") if isinstance(c.get("_account"), dict) else {}
                    )
                    cred = c.get("credentials") if isinstance(c.get("credentials"), dict) else {}
                    if not cred and isinstance(acc.get("credentials"), dict):
                        cred = acc["credentials"]
                    account_id = c.get("id") if c.get("id") is not None else acc.get("id")
                    email_out = (
                        email_hint
                        or c.get("email")
                        or cred.get("email")
                        or acc.get("name")
                        or c.get("name")
                        or None
                    )
                    item = {
                        "index": idx,
                        "email": email_out,
                        "sso_hint": sso_hint,
                        "status": "ok",
                        "account_id": account_id,
                        "action": "sso_to_oauth",
                        "group_id": group_id,
                        "user_id": cred.get("user_id")
                        or cred.get("sub")
                        or c.get("user_id")
                        or acc.get("user_id"),
                        "expires_at": cred.get("expires_at")
                        or c.get("expires_at")
                        or acc.get("expires_at"),
                        "has_refresh_token": bool(
                            cred.get("refresh_token")
                            or (acc.get("credentials_status") or {}).get("has_refresh_token")
                        ),
                        "via": "sso_to_oauth_http",
                    }
                    sso_api_hits += 1
                    _mark_ok(item)
                    results_by_idx[idx] = item
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 成功(sso_to_oauth_http): "
                        f"{item.get('email') or item.get('user_id') or 'ok'}"
                        f" · id={account_id} · group={group_id}",
                        "success",
                    )
                else:
                    err = failed_by_index.get(bi) or "sso-to-oauth 未返回成功"
                    # 无效 SSO 不重试；限流/超时等可走本机 device flow
                    err_l = err.lower()
                    invalid = (
                        "unauthorized" in err_l
                        or "invalid" in err_l
                        or "expired" in err_l
                        or "会话无效" in err
                        or "非有效" in err
                    )
                    item = {
                        "index": idx,
                        "email": email_hint or None,
                        "sso_hint": sso_hint,
                        "status": "failed",
                        "error": err,
                        "retryable": not invalid,
                        "via": "sso_to_oauth_http",
                    }
                    results_by_idx[idx] = item
                    fail_count += 1
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 失败(sso_to_oauth_http): {err}",
                        "warn",
                    )

    # —— 路径 C：sso-to-oauth 可重试失败 → 本机 device flow 兜底 + HTTP 写 accounts ——
    retry_list = [
        idx
        for idx in range(1, len(items) + 1)
        if results_by_idx.get(idx, {}).get("status") == "failed"
        and results_by_idx[idx].get("retryable", False)
        and results_by_idx[idx].get("via") == "sso_to_oauth_http"
    ]
    if retry_list:
        logs.emit(
            f"sub2api 导入：sso-to-oauth 后 {len(retry_list)} 条可重试，"
            f"启用本机 device flow 兜底换票…",
            "warn",
        )
        for j, idx in enumerate(retry_list):
            if j > 0:
                time.sleep(5.0)
            email_hint = items[idx - 1].get("email") or ""
            sso = items[idx - 1].get("sso") or ""
            sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso
            flow, last_flow_err = _device_flow_to_token(
                sso, idx, pass_label="·兜底", max_attempts=4
            )
            if not flow or not flow.get("token"):
                item = {
                    "index": idx,
                    "email": email_hint or None,
                    "sso_hint": sso_hint,
                    "status": "failed",
                    "error": last_flow_err or "本机 device flow 失败",
                    "via": "device_flow_http",
                }
                results_by_idx[idx] = item
                logs.emit(
                    f"sub2api 导入·兜底 [{idx}/{len(items)}] 仍失败: {item.get('error')}",
                    "warn",
                )
                continue
            try:
                entry = token_to_auth_entry(flow["token"], email=email_hint or "")
                # 兜底换到的票也落盘，避免下次重启又要重换
                append_token_record(
                    email_hint or "", flow["token"], sso=sso, note="import_fallback"
                )
                item = _write_token_to_sub2api(entry, email_hint or "", idx)
                item["sso_hint"] = sso_hint
                item["via"] = "device_flow_http"
                if item.get("status") == "ok":
                    flow_hits += 1
                    fail_count = max(0, fail_count - 1)
                    _mark_ok(item)
                    results_by_idx[idx] = item
                    logs.emit(
                        f"sub2api 导入·兜底 [{idx}/{len(items)}] 成功(device_flow_http): "
                        f"{item.get('email') or item.get('user_id') or 'ok'}",
                        "success",
                    )
                else:
                    results_by_idx[idx] = item
                    logs.emit(
                        f"sub2api 导入·兜底 [{idx}/{len(items)}] 写库失败: {item.get('error')}",
                        "warn",
                    )
            except Exception as e:
                results_by_idx[idx] = {
                    "index": idx,
                    "email": email_hint or None,
                    "sso_hint": sso_hint,
                    "status": "failed",
                    "error": f"兜底异常: {e}",
                    "via": "device_flow_http",
                }
                logs.emit(f"sub2api 导入·兜底 [{idx}/{len(items)}] 异常: {e}", "error")

    # 补全未处理 index（理论上不应有）
    for idx in range(1, len(items) + 1):
        if idx not in results_by_idx:
            fail_count += 1
            results_by_idx[idx] = {
                "index": idx,
                "email": items[idx - 1].get("email") or None,
                "status": "failed",
                "error": "未处理",
                "via": "error",
            }

    results = [results_by_idx[i] for i in sorted(results_by_idx)]
    msg = (
        f"SSO 导入 sub2api(HTTP) 完成：{ok_count} 成功, {fail_count} 失败"
        f"（缓存直写 {cached_hits}，sso-to-oauth {sso_api_hits}，device flow {flow_hits}）"
    )
    return {
        "ok": fail_count == 0 and ok_count > 0,
        "message": msg,
        "success": ok_count,
        "fail": fail_count,
        "total": len(items),
        "cached_hits": cached_hits,
        "sso_api_hits": sso_api_hits,
        "flow_hits": flow_hits,
        "results": results,
        "imported": imported,
        "base_url": api_base,
        "group_id": str(group_id),
        "group_name": sub2.get("group_name"),
        "mode": "http_admin_api",
    }

def mask_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * min(12, len(value) - keep * 2) + value[-keep:]


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "grok-register-ui"})


@app.get("/api/status")
def status():
    data = engine.get_status()
    data["env"] = env_snapshot()
    try:
        data["solver"] = solver_manager.status()
    except Exception as e:
        data["solver"] = {"ready": False, "message": f"状态读取失败: {e}"}
    return jsonify(data)


@app.get("/api/config")
def get_config():
    cfg = read_env_file()
    manual_email = os.getenv("MANUAL_EMAIL", "")
    if not manual_email and ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if raw.startswith("MANUAL_EMAIL="):
                manual_email = raw.split("=", 1)[1].strip().strip('"').strip("'")
                break
    return jsonify({
        "ok": True,
        "config": {
            "WORKER_DOMAIN": cfg.get("WORKER_DOMAIN", ""),
            "FREEMAIL_TOKEN": cfg.get("FREEMAIL_TOKEN", ""),
            "FREEMAIL_DOMAIN": cfg.get("FREEMAIL_DOMAIN", DEFAULTS["FREEMAIL_DOMAIN"]),
            "FREEMAIL_API_STYLE": cfg.get("FREEMAIL_API_STYLE", DEFAULTS["FREEMAIL_API_STYLE"]),
            "YESCAPTCHA_KEY": cfg.get("YESCAPTCHA_KEY", ""),
            "SOLVER_URL": cfg.get("SOLVER_URL", DEFAULTS["SOLVER_URL"]),
            "SOLVER_BROWSER": cfg.get("SOLVER_BROWSER", DEFAULTS["SOLVER_BROWSER"]),
            "SOLVER_THREADS": cfg.get("SOLVER_THREADS", DEFAULTS["SOLVER_THREADS"]),
            "SOLVER_HOST": cfg.get("SOLVER_HOST", DEFAULTS["SOLVER_HOST"]),
            "SOLVER_PORT": cfg.get("SOLVER_PORT", DEFAULTS["SOLVER_PORT"]),
            "SOLVER_DEBUG": cfg.get("SOLVER_DEBUG", DEFAULTS["SOLVER_DEBUG"]),
            "UI_HOST": cfg.get("UI_HOST", DEFAULTS["UI_HOST"]),
            "UI_PORT": cfg.get("UI_PORT", DEFAULTS["UI_PORT"]),
            "GROK_PROXY": cfg.get("GROK_PROXY", DEFAULTS.get("GROK_PROXY", "")),
            "MANUAL_EMAIL": manual_email,
            # 前端 textarea 用换行；.env 内部是分号
            "GROK_PROXY_LIST": _normalize_proxy_list_text(
                cfg.get("GROK_PROXY_LIST", DEFAULTS.get("GROK_PROXY_LIST", ""))
            ),
            "GROK_SS_DENY_BREAK": cfg.get(
                "GROK_SS_DENY_BREAK", DEFAULTS.get("GROK_SS_DENY_BREAK", "3")
            ),
            "GROK_SS_PROXY_SWITCH_LIMIT": cfg.get(
                "GROK_SS_PROXY_SWITCH_LIMIT",
                DEFAULTS.get("GROK_SS_PROXY_SWITCH_LIMIT", "3"),
            ),
            "GROK_SS_COOLDOWN_SEC": cfg.get(
                "GROK_SS_COOLDOWN_SEC", DEFAULTS.get("GROK_SS_COOLDOWN_SEC", "60")
            ),
            "SUB2API_URL": cfg.get("SUB2API_URL", cfg.get("UPSTREAM_URL", DEFAULTS["SUB2API_URL"])),
            "SUB2API_DOCKER_CONTAINER": cfg.get("SUB2API_DOCKER_CONTAINER", DEFAULTS["SUB2API_DOCKER_CONTAINER"]),
            "SUB2API_DB_HOST": cfg.get("SUB2API_DB_HOST", DEFAULTS["SUB2API_DB_HOST"]),
            "SUB2API_DB_PORT": cfg.get("SUB2API_DB_PORT", DEFAULTS["SUB2API_DB_PORT"]),
            "SUB2API_DB_NAME": cfg.get("SUB2API_DB_NAME", DEFAULTS["SUB2API_DB_NAME"]),
            "SUB2API_DB_USER": cfg.get("SUB2API_DB_USER", DEFAULTS["SUB2API_DB_USER"]),
            "SUB2API_DB_PASSWORD": cfg.get("SUB2API_DB_PASSWORD", DEFAULTS["SUB2API_DB_PASSWORD"]),
            "SUB2API_GROK_GROUP_ID": cfg.get("SUB2API_GROK_GROUP_ID", DEFAULTS["SUB2API_GROK_GROUP_ID"]),
            "SUB2API_GROK_GROUP_NAME": cfg.get("SUB2API_GROK_GROUP_NAME", DEFAULTS["SUB2API_GROK_GROUP_NAME"]),
            "UPSTREAM_URL": cfg.get("SUB2API_URL", cfg.get("UPSTREAM_URL", DEFAULTS["SUB2API_URL"])),
            "UPSTREAM_ADMIN_EMAIL": cfg.get("UPSTREAM_ADMIN_EMAIL", ""),
            "UPSTREAM_ADMIN_PASSWORD": cfg.get("UPSTREAM_ADMIN_PASSWORD", ""),
            "captcha_mode": "yescaptcha" if cfg.get("YESCAPTCHA_KEY", "").strip() else "local",
        },
        "masked": {
            "FREEMAIL_TOKEN": mask_secret(cfg.get("FREEMAIL_TOKEN", "")),
            "YESCAPTCHA_KEY": mask_secret(cfg.get("YESCAPTCHA_KEY", "")),
            "SUB2API_DB_PASSWORD": mask_secret(cfg.get("SUB2API_DB_PASSWORD", DEFAULTS["SUB2API_DB_PASSWORD"])),
            "UPSTREAM_ADMIN_PASSWORD": mask_secret(cfg.get("UPSTREAM_ADMIN_PASSWORD", "")),
        },
    })


@app.get("/api/mail-domains")
def mail_domains():
    """从 freemail / cloudflare_temp_email 自动拉取可用邮箱域名"""
    from g.email_service import EmailService

    worker = request.args.get("worker_domain")
    token = request.args.get("token")
    # 未传 token 时用已保存配置；传空字符串表示无密码
    if token is None:
        token = read_env_file().get("FREEMAIL_TOKEN", "")
    if worker is None:
        worker = read_env_file().get("WORKER_DOMAIN", "")
    try:
        result = EmailService.fetch_mail_domains(worker_domain=worker, token=token)
        code = 200 if result.get("ok") else 502
        return jsonify(result), code
    except Exception as e:
        return jsonify({
            "ok": False,
            "domains": [],
            "default_domains": [],
            "selected": "auto",
            "message": str(e),
            "settings": {},
        }), 500


@app.post("/api/config")
def save_config():
    if engine.is_running():
        return jsonify({"ok": False, "message": "任务运行中，请先停止再修改配置"}), 409

    body = request.get_json(silent=True) or {}
    current = read_env_file()

    worker = str(body.get("WORKER_DOMAIN", current.get("WORKER_DOMAIN", ""))).strip()
    token = str(body.get("FREEMAIL_TOKEN", current.get("FREEMAIL_TOKEN", ""))).strip()
    mail_domain = str(body.get("FREEMAIL_DOMAIN", current.get("FREEMAIL_DOMAIN", DEFAULTS["FREEMAIL_DOMAIN"]))).strip() or "auto"
    api_style = str(body.get("FREEMAIL_API_STYLE", current.get("FREEMAIL_API_STYLE", DEFAULTS["FREEMAIL_API_STYLE"]))).strip() or "auto"
    yes = str(body.get("YESCAPTCHA_KEY", current.get("YESCAPTCHA_KEY", ""))).strip()
    solver = str(body.get("SOLVER_URL", current.get("SOLVER_URL", DEFAULTS["SOLVER_URL"]))).strip()
    solver_browser = str(body.get("SOLVER_BROWSER", current.get("SOLVER_BROWSER", DEFAULTS["SOLVER_BROWSER"]))).strip() or "camoufox"
    solver_threads = str(body.get("SOLVER_THREADS", current.get("SOLVER_THREADS", DEFAULTS["SOLVER_THREADS"]))).strip() or "2"
    solver_host = str(body.get("SOLVER_HOST", current.get("SOLVER_HOST", DEFAULTS["SOLVER_HOST"]))).strip() or "127.0.0.1"
    solver_port = str(body.get("SOLVER_PORT", current.get("SOLVER_PORT", DEFAULTS["SOLVER_PORT"]))).strip() or "5072"
    solver_debug = str(body.get("SOLVER_DEBUG", current.get("SOLVER_DEBUG", DEFAULTS["SOLVER_DEBUG"]))).strip() or "1"
    ui_host = str(body.get("UI_HOST", current.get("UI_HOST", DEFAULTS["UI_HOST"]))).strip() or "127.0.0.1"
    ui_port = str(body.get("UI_PORT", current.get("UI_PORT", DEFAULTS["UI_PORT"]))).strip() or "3333"
    # 代理：前端显式传空表示直连；未传则保留已有
    if "GROK_PROXY" in body:
        grok_proxy = str(body.get("GROK_PROXY") or "").strip()
    else:
        grok_proxy = str(current.get("GROK_PROXY", DEFAULTS.get("GROK_PROXY", "")) or "").strip()
    # 代理池：多行/分号；优先于单条 GROK_PROXY
    if "GROK_PROXY_LIST" in body:
        grok_proxy_list_raw = str(body.get("GROK_PROXY_LIST") or "")
    else:
        grok_proxy_list_raw = str(
            current.get("GROK_PROXY_LIST", DEFAULTS.get("GROK_PROXY_LIST", "")) or ""
        )
    # 熔断自定义
    if "GROK_SS_DENY_BREAK" in body:
        ss_deny_break = str(body.get("GROK_SS_DENY_BREAK") or "").strip()
    else:
        ss_deny_break = str(
            current.get("GROK_SS_DENY_BREAK", DEFAULTS["GROK_SS_DENY_BREAK"]) or "3"
        ).strip()
    if "GROK_SS_PROXY_SWITCH_LIMIT" in body:
        ss_switch_limit = str(body.get("GROK_SS_PROXY_SWITCH_LIMIT") or "").strip()
    else:
        ss_switch_limit = str(
            current.get(
                "GROK_SS_PROXY_SWITCH_LIMIT", DEFAULTS["GROK_SS_PROXY_SWITCH_LIMIT"]
            )
            or "3"
        ).strip()
    if "GROK_SS_COOLDOWN_SEC" in body:
        ss_cooldown = str(body.get("GROK_SS_COOLDOWN_SEC") or "").strip()
    else:
        ss_cooldown = str(
            current.get("GROK_SS_COOLDOWN_SEC", DEFAULTS["GROK_SS_COOLDOWN_SEC"]) or "60"
        ).strip()
    sub2api_url = str(body.get("SUB2API_URL", body.get("UPSTREAM_URL", current.get("SUB2API_URL", current.get("UPSTREAM_URL", DEFAULTS["SUB2API_URL"]))))).strip()
    sub2api_container = str(body.get("SUB2API_DOCKER_CONTAINER", current.get("SUB2API_DOCKER_CONTAINER", DEFAULTS["SUB2API_DOCKER_CONTAINER"]))).strip() or DEFAULTS["SUB2API_DOCKER_CONTAINER"]
    sub2api_db_host = str(body.get("SUB2API_DB_HOST", current.get("SUB2API_DB_HOST", DEFAULTS["SUB2API_DB_HOST"]))).strip() or DEFAULTS["SUB2API_DB_HOST"]
    sub2api_db_port = str(body.get("SUB2API_DB_PORT", current.get("SUB2API_DB_PORT", DEFAULTS["SUB2API_DB_PORT"]))).strip() or DEFAULTS["SUB2API_DB_PORT"]
    sub2api_db_name = str(body.get("SUB2API_DB_NAME", current.get("SUB2API_DB_NAME", DEFAULTS["SUB2API_DB_NAME"]))).strip() or DEFAULTS["SUB2API_DB_NAME"]
    sub2api_db_user = str(body.get("SUB2API_DB_USER", current.get("SUB2API_DB_USER", DEFAULTS["SUB2API_DB_USER"]))).strip() or DEFAULTS["SUB2API_DB_USER"]
    sub2api_db_password = str(body.get("SUB2API_DB_PASSWORD", current.get("SUB2API_DB_PASSWORD", DEFAULTS["SUB2API_DB_PASSWORD"]))).strip() or DEFAULTS["SUB2API_DB_PASSWORD"]
    # 页面只维护分组名称；ID 由连通测试/导入时自动拉取并回写
    sub2api_group_name = str(
        body.get(
            "SUB2API_GROK_GROUP_NAME",
            current.get("SUB2API_GROK_GROUP_NAME", DEFAULTS["SUB2API_GROK_GROUP_NAME"]),
        )
    ).strip() or DEFAULTS["SUB2API_GROK_GROUP_NAME"]
    # 兼容旧前端仍传 ID：有则暂存，最终以名称解析结果为准
    sub2api_group_id = str(
        body.get(
            "SUB2API_GROK_GROUP_ID",
            current.get("SUB2API_GROK_GROUP_ID", DEFAULTS["SUB2API_GROK_GROUP_ID"]),
        )
        or ""
    ).strip()
    upstream_url = sub2api_url
    upstream_email = str(body.get("UPSTREAM_ADMIN_EMAIL", current.get("UPSTREAM_ADMIN_EMAIL", ""))).strip()
    upstream_pwd = str(body.get("UPSTREAM_ADMIN_PASSWORD", current.get("UPSTREAM_ADMIN_PASSWORD", ""))).strip()

    # 允许前端传空密钥表示“保留原值”：用特殊标记
    if body.get("FREEMAIL_TOKEN") is None:
        token = current.get("FREEMAIL_TOKEN", "")
    if body.get("YESCAPTCHA_KEY") is None:
        yes = current.get("YESCAPTCHA_KEY", "")
    if body.get("UPSTREAM_ADMIN_EMAIL") is None:
        upstream_email = current.get("UPSTREAM_ADMIN_EMAIL", "")
    if body.get("UPSTREAM_ADMIN_PASSWORD") is None:
        upstream_pwd = current.get("UPSTREAM_ADMIN_PASSWORD", "")

    captcha_mode = str(body.get("captcha_mode", "")).strip().lower()
    if captcha_mode == "local":
        # 本地 solver 模式可清空 yescaptcha
        if "YESCAPTCHA_KEY" in body and body.get("YESCAPTCHA_KEY") == "":
            yes = ""

    # 规范化 worker 域名
    worker = worker.replace("https://", "").replace("http://", "").strip().rstrip("/")
    # 邮箱后缀多选：domain1,domain2 或 auto
    mail_domain = _normalize_mail_domains(mail_domain)
    # 代理池规范化 + 格式校验
    proxy_lines = _split_proxy_lines(grok_proxy_list_raw)
    # 兼容：池空但单条有值 → 当池只有一条
    if not proxy_lines and grok_proxy:
        proxy_lines = [grok_proxy]
    invalid_proxies: list[str] = []
    if proxy_lines:
        try:
            from g.same_session_register import parse_proxy_spec as _parse_px
        except Exception:
            _parse_px = None
        if _parse_px:
            for i, line in enumerate(proxy_lines, 1):
                if not _parse_px(line):
                    show = line if len(line) <= 48 else (line[:24] + "…" + line[-12:])
                    invalid_proxies.append(f"#{i} {show}")
        if invalid_proxies:
            return jsonify({
                "ok": False,
                "message": "代理格式错误: " + "; ".join(invalid_proxies[:5])
                + (" …" if len(invalid_proxies) > 5 else "")
                + "。支持 host:port · http/socks5:// · user:pass@host:port · host:port:user:pass",
            }), 400
    grok_proxy_list = _proxy_list_for_env("\n".join(proxy_lines))
    # 单条字段：池首条（兼容旧逻辑）；池空则直连
    grok_proxy = proxy_lines[0] if proxy_lines else ""

    # 熔断参数校验
    def _parse_nonneg_int(raw: str, default: int, name: str, lo: int = 0, hi: int = 86400):
        s = (raw or "").strip().lower()
        if s in ("", "off", "false", "no", "none"):
            return "0" if name != "GROK_SS_COOLDOWN_SEC" else str(default)
        try:
            n = int(s)
        except ValueError:
            raise ValueError(f"{name} 必须是整数")
        if n < lo or n > hi:
            raise ValueError(f"{name} 范围 {lo}-{hi}")
        return str(n)

    try:
        ss_deny_break = _parse_nonneg_int(ss_deny_break, 3, "GROK_SS_DENY_BREAK", 0, 100)
        ss_switch_limit = _parse_nonneg_int(
            ss_switch_limit, 3, "GROK_SS_PROXY_SWITCH_LIMIT", 0, 50
        )
        ss_cooldown = _parse_nonneg_int(ss_cooldown, 60, "GROK_SS_COOLDOWN_SEC", 0, 86400)
    except ValueError as ve:
        return jsonify({"ok": False, "message": str(ve)}), 400

    sub2api_url = normalize_upstream_url(sub2api_url) or DEFAULTS["SUB2API_URL"]
    upstream_url = sub2api_url

    # 手动邮箱模式（MANUAL_EMAIL）：前端显式传才更新；不传保留旧值
    manual_email = ""
    if "manual_email" in body:
        manual_email = str(body.get("manual_email") or "").strip()

    if not re.fullmatch(r"\d{2,5}", ui_port):
        return jsonify({"ok": False, "message": "UI_PORT 必须是 2-5 位数字"}), 400
    if not re.fullmatch(r"\d{2,5}", solver_port):
        return jsonify({"ok": False, "message": "SOLVER_PORT 必须是 2-5 位数字"}), 400
    if not re.fullmatch(r"\d{1,2}", solver_threads) or not (1 <= int(solver_threads) <= 16):
        return jsonify({"ok": False, "message": "SOLVER_THREADS 范围 1-16"}), 400
    if not re.fullmatch(r"\d{2,5}", sub2api_db_port):
        return jsonify({"ok": False, "message": "SUB2API_DB_PORT 必须是 2-5 位数字"}), 400
    if not sub2api_group_name:
        return jsonify({"ok": False, "message": "请填写分组名称"}), 400
    # 旧缓存 ID 可保留；非法则清空，等名称解析后回写
    if sub2api_group_id and not re.fullmatch(r"\d+", sub2api_group_id):
        sub2api_group_id = ""
    if solver_browser not in ("camoufox", "chromium", "chrome", "msedge"):
        return jsonify({"ok": False, "message": "SOLVER_BROWSER 不支持该值"}), 400
    if not solver:
        solver = DEFAULTS["SOLVER_URL"]

    values = {
        "WORKER_DOMAIN": worker,
        "FREEMAIL_TOKEN": token,
        "FREEMAIL_DOMAIN": mail_domain,
        "FREEMAIL_API_STYLE": api_style,
        "YESCAPTCHA_KEY": yes,
        "SOLVER_URL": solver,
        "SOLVER_BROWSER": solver_browser,
        "SOLVER_THREADS": solver_threads,
        "SOLVER_HOST": solver_host,
        "SOLVER_PORT": solver_port,
        "SOLVER_DEBUG": "1" if solver_debug not in ("0", "false", "False") else "0",
        "UI_HOST": ui_host,
        "UI_PORT": ui_port,
        "GROK_PROXY": grok_proxy,
        "GROK_PROXY_LIST": grok_proxy_list,
        "GROK_SS_DENY_BREAK": ss_deny_break,
        "GROK_SS_PROXY_SWITCH_LIMIT": ss_switch_limit,
        "GROK_SS_COOLDOWN_SEC": ss_cooldown,
        "SUB2API_URL": sub2api_url,
        "SUB2API_DOCKER_CONTAINER": sub2api_container,
        "SUB2API_DB_HOST": sub2api_db_host,
        "SUB2API_DB_PORT": sub2api_db_port,
        "SUB2API_DB_NAME": sub2api_db_name,
        "SUB2API_DB_USER": sub2api_db_user,
        "SUB2API_DB_PASSWORD": sub2api_db_password,
        "SUB2API_GROK_GROUP_ID": sub2api_group_id,
        "SUB2API_GROK_GROUP_NAME": sub2api_group_name,
        "UPSTREAM_URL": upstream_url,
        "UPSTREAM_ADMIN_EMAIL": upstream_email,
        "UPSTREAM_ADMIN_PASSWORD": upstream_pwd,
        "MANUAL_EMAIL": manual_email,
    }
    # 手动邮箱只在「运行」页显式传时才更新，配置页保存不覆盖
    if "manual_email" not in body:
        values.pop("MANUAL_EMAIL", None)
    try:
        write_env_file(values)
        apply_env_to_process(values)
        px_n = len(proxy_lines)
        logs.emit(
            f"配置已保存到 .env（邮箱域名: {mail_domain}"
            f" · 代理池 {px_n} 条"
            f" · 熔断 deny={ss_deny_break}/切代理={ss_switch_limit}/冷却={ss_cooldown}s）",
            "success",
        )

        # 保存后自动测试 sub2api HTTP 通道，并按名称解析 group_id 回写
        upstream_test = None
        if sub2api_url and upstream_email and upstream_pwd and sub2api_group_name:
            try:
                upstream_test = test_upstream_connectivity(
                    sub2api_url,
                    password=upstream_pwd,
                    email=upstream_email,
                    group_name=sub2api_group_name,
                    group_id=sub2api_group_id or None,
                )
                level = "success" if upstream_test.get("ok") else "warn"
                logs.emit(f"sub2api 连通性: {upstream_test.get('message')}", level)
                if upstream_test.get("ok") and isinstance(upstream_test.get("group"), dict):
                    g = upstream_test["group"]
                    if g.get("group_id") is not None:
                        sub2api_group_id = str(g.get("group_id"))
                        values["SUB2API_GROK_GROUP_ID"] = sub2api_group_id
                    if g.get("group_name"):
                        sub2api_group_name = str(g.get("group_name"))
                        values["SUB2API_GROK_GROUP_NAME"] = sub2api_group_name
                    # 再写一次，保证返回/侧栏立刻是解析后的 ID
                    try:
                        write_env_file(values)
                        apply_env_to_process({
                            "SUB2API_GROK_GROUP_ID": values.get("SUB2API_GROK_GROUP_ID", ""),
                            "SUB2API_GROK_GROUP_NAME": values.get("SUB2API_GROK_GROUP_NAME", ""),
                        })
                    except Exception:
                        pass
            except Exception as te:
                upstream_test = {"ok": False, "message": str(te)}
                logs.emit(f"sub2api 连通性测试异常: {te}", "warn")

        msg = "配置已保存"
        if upstream_test is not None:
            if upstream_test.get("ok"):
                g = upstream_test.get("group") or {}
                msg += f"；sub2api 连通正常，分组 {g.get('group_name') or sub2api_group_name} → id={g.get('group_id') or sub2api_group_id or '?'}"
            else:
                msg += f"；sub2api 连通失败: {upstream_test.get('message')}"

        return jsonify({
            "ok": True,
            "message": msg,
            "env": env_snapshot(),
            "config": values,
            "upstream_test": upstream_test,
        })
    except Exception as e:
        return jsonify({"ok": False, "message": f"保存失败: {e}"}), 500


@app.get("/api/solver/status")
def solver_status():
    try:
        return jsonify({"ok": True, **solver_manager.status()})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.post("/api/solver/start")
def solver_start():
    body = request.get_json(silent=True) or {}
    wait = body.get("wait", True)
    try:
        timeout = float(body.get("timeout", 90))
    except (TypeError, ValueError):
        timeout = 90.0
    try:
        result = solver_manager.start(wait_ready=bool(wait), timeout=timeout)
        if result.get("ok"):
            logs.emit(result.get("message") or "Solver 已启动", "success")
        else:
            logs.emit(result.get("message") or "Solver 启动失败", "error")
        code = 200 if result.get("ok") else 500
        return jsonify(result), code
    except Exception as e:
        logs.emit(f"Solver 启动异常: {e}", "error")
        return jsonify({"ok": False, "message": str(e)}), 500


@app.post("/api/solver/stop")
def solver_stop():
    try:
        result = solver_manager.stop()
        level = "success" if result.get("ok") else "warn"
        logs.emit(result.get("message") or "Solver 已停止", level)
        code = 200 if result.get("ok") else 500
        return jsonify(result), code
    except Exception as e:
        logs.emit(f"Solver 停止异常: {e}", "error")
        return jsonify({"ok": False, "message": str(e)}), 500


@app.get("/api/logs")
def get_logs():
    after_id = request.args.get("after_id", 0, type=int)
    post_after_id = request.args.get("post_after_id", 0, type=int)
    limit = request.args.get("limit", 200, type=int)
    limit = max(1, min(limit, 500))
    latest = logs.latest_id()
    post_latest = post_logs.latest_id()
    # after_id 大于服务端序号 = 页面是旧会话，需重置游标
    reset = bool(after_id and after_id > latest)
    post_reset = bool(post_after_id and post_after_id > post_latest)
    return jsonify({
        "logs": logs.since(after_id, limit),
        "latest_id": latest,
        "reset": reset,
        # 右侧：risk / 换 token
        "post_logs": post_logs.since(post_after_id, limit),
        "post_latest_id": post_latest,
        "post_reset": post_reset,
    })


@app.post("/api/start")
def start():
    body = request.get_json(silent=True) or {}
    workers = body.get("workers", 8)
    target = body.get("target", 100)
    mode_raw = body.get("mode") or body.get("register_mode") or ""
    manual_email = str(body.get("manual_email") or "").strip()
    try:
        workers = int(workers)
        target = int(target)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "并发数/数量必须是整数"}), 400

    if workers < 1 or workers > 64:
        return jsonify({"ok": False, "message": "并发数范围 1-64"}), 400
    if target < 1 or target > 100000:
        return jsonify({"ok": False, "message": "注册数量范围 1-100000"}), 400

    # 注册路径：same_session（默认 CLEAN）/ protocol（旧混合）
    try:
        from grok import resolve_register_mode

        reg_mode = resolve_register_mode(mode_raw or None)
    except Exception:
        reg_mode = (mode_raw or "same_session").strip().lower() or "same_session"

    # 手动模式（manual_emails 多邮箱列表）：不要求 Worker/Token；按粘贴邮箱数量执行；
    # Turnstile 仍由本地 Solver 自动解
    manual_emails_raw = body.get("manual_emails")
    if isinstance(manual_emails_raw, list):
        manual_emails = [str(x).strip() for x in manual_emails_raw if str(x).strip()]
    else:
        manual_emails = [manual_email] if manual_email else []
    manual_mode = bool(manual_emails)
    if manual_mode:
        try:
            (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
            (BASE_DIR / "logs" / "manual_emails.txt").write_text(
                "\n".join(manual_emails) + "\n", encoding="utf-8"
            )
            write_env_file({"MANUAL_EMAIL": manual_emails[0]})
            apply_env_to_process({"MANUAL_EMAIL": manual_emails[0]})
        except Exception as e:
            logs.emit(f"手动邮箱写入失败: {e}", "warn")
        workers = max(1, min(len(manual_emails), 8))
        target = len(manual_emails)
        logs.emit(
            f"手动模式：{len(manual_emails)} 个邮箱，按粘贴数量执行"
            f"（并发 {workers}，Worker/Token 无需配置）",
            "info",
        )
    else:
        env = env_snapshot()
        if not env["worker_domain_set"] or not env["freemail_token_set"]:
            return jsonify({
                "ok": False,
                "message": "请先在「配置」中填写 WORKER_DOMAIN 与 FREEMAIL_TOKEN",
            }), 400

    # 本地 Solver 模式：开任务前自动确保 5072 在线（注册机与 Solver 是两个进程）
    cfg_env = read_env_file()
    use_local_solver = not (cfg_env.get("YESCAPTCHA_KEY") or "").strip()
    solver_info = None
    if use_local_solver:
        # Solver 默认只有 2 个浏览器；并发远大于线程数会堆队列，也更容易把进程拖崩
        try:
            solver_threads = int(cfg_env.get("SOLVER_THREADS") or "2")
        except ValueError:
            solver_threads = 2
        solver_threads = max(1, min(solver_threads, 16))
        # same_session 还要跑 Camoufox 注册浏览器，并发更要克制
        if reg_mode == "same_session" and workers > max(2, solver_threads):
            logs.emit(
                f"提示：same_session 路径并发 {workers}，建议 ≤ {max(2, min(4, solver_threads))} "
                f"（注册浏览器 + Solver 双开）",
                "warn",
            )
        elif workers > solver_threads * 2:
            logs.emit(
                f"提示：并发 {workers} 远大于 Solver 浏览器数 {solver_threads}，"
                f"建议并发 ≤ {solver_threads * 2}，或在配置里提高 SOLVER_THREADS 后重启 Solver",
                "warn",
            )
        elif workers > solver_threads:
            logs.emit(
                f"提示：并发 {workers} > Solver 浏览器 {solver_threads}，"
                f"Turnstile 会排队；机器够用可把 SOLVER_THREADS 调到 {workers}",
                "info",
            )

        logs.emit("检查 Turnstile Solver（5072）…", "info")
        try:
            solver_info = solver_manager.ensure_ready(timeout=120.0)
        except Exception as e:
            solver_info = {"ok": False, "message": f"Solver 检查异常: {e}"}
        if not solver_info.get("ok") or not solver_info.get("ready"):
            msg = solver_info.get("message") or "Turnstile Solver 未就绪"
            logs.emit(f"Solver 未就绪，无法开始注册: {msg}", "error")
            return jsonify({
                "ok": False,
                "message": (
                    f"Turnstile Solver 离线/未就绪：{msg}。"
                    "请点「启动 Solver」，或运行 TurnstileSolver.bat / "
                    "python solver_manager.py start，并查看 logs/turnstile_solver.log"
                ),
                "solver": solver_info,
            }), 503
        if solver_info.get("started"):
            logs.emit(solver_info.get("message") or "Solver 已自动启动", "success")
        else:
            logs.emit("Solver 已在线", "info")

        # 任务期间后台看门狗：Solver 中途崩溃自动拉起
        try:
            wd = solver_manager.start_watchdog(
                log_fn=lambda msg, level="info": logs.emit(msg, level),
                interval=6.0,
            )
            logs.emit(wd.get("message") or "Solver 看门狗已启动", "info")
        except Exception as e:
            logs.emit(f"Solver 看门狗启动失败（任务仍继续）: {e}", "warn")

    logs.emit(f"注册路径: {reg_mode}", "info")
    result = engine.start(workers=workers, target=target, blocking=False, mode=reg_mode)
    if not result.get("ok") and use_local_solver:
        try:
            solver_manager.stop_watchdog()
        except Exception:
            pass
    if solver_info is not None:
        result["solver"] = {
            "ready": bool(solver_info.get("ready")),
            "pid": solver_info.get("pid"),
            "message": solver_info.get("message"),
            "auto_started": bool(solver_info.get("started")),
            "watchdog": solver_manager.watchdog_running(),
        }
    code = 200 if result.get("ok") else 409
    return jsonify(result), code


@app.post("/api/stop")
def stop():
    try:
        solver_manager.stop_watchdog()
    except Exception:
        pass
    result = engine.stop()
    code = 200 if result.get("ok") else 409
    return jsonify(result), code


@app.post("/api/logs/clear")
def clear_logs():
    logs.clear()
    post_logs.clear()
    logs.emit("日志已清空", "info")
    post_logs.emit("Risk/换 token 日志已清空", "info")
    return jsonify({"ok": True})


@app.post("/api/grok-test")
def api_grok_test():
    """Grok 4.5 功能测试：粘贴 SSO →（可选 device flow 换 token）→ grok -p 测试。

    body: {sso, sso_rw?, exchange=True, message="hi", model="grok-4.5"}
    """
    import json as _json
    import os as _os
    import shutil as _shutil
    import subprocess as _subprocess
    import sys as _sys
    import time as _time

    from test_grok45 import GROK, AUTH_FILE, BACKUP, build_auth  # noqa: E402

    body = request.get_json(silent=True) or {}
    raw = str(body.get("sso") or "").strip()
    sso_rw = str(body.get("sso_rw") or "").strip()
    exchange = bool(body.get("exchange", True))
    message_text = str(body.get("message") or "").strip() or "hi"
    model = str(body.get("model") or "").strip() or "grok-4.5"
    if not raw:
        return jsonify({"ok": False, "error": "未提供 SSO（先在成功列表点「复制」）"})
    if "----" in raw:
        parts = raw.split("----")
        if len(parts) >= 2:
            if not sso_rw and len(parts) >= 3:
                sso_rw = parts[2].strip()
            raw = parts[1].strip()

    tok = {}
    if exchange:
        try:
            ws = r"D:\workspace\34"
            if ws not in _sys.path:
                _sys.path.insert(0, ws)
            from device_flow import device_flow_to_token  # noqa: E402

            flow = device_flow_to_token(raw, issue_token=True)
        except Exception as e:
            return jsonify({"ok": False, "error": f"device flow 换 token 异常: {e}"})
        if not flow.get("ok") or not flow.get("token"):
            return jsonify(
                {"ok": False, "error": f"换 token 失败: {flow.get('error') or '未知'}"}
            )
        tok = dict(flow["token"])
        tok.setdefault("email", str(body.get("email") or ""))
    else:
        return jsonify({
            "ok": False,
            "error": "关闭「自动换取 token」时需直接提供 access_token（当前面板只支持 SSO 输入，请保持开关开启）",
        })

    try:
        auth = build_auth(tok)
    except Exception as e:
        return jsonify({"ok": False, "error": f"转换 auth 失败: {e}"})

    account = ""
    for _v in auth.values():
        if isinstance(_v, dict):
            account = (
                _v.get("email")
                or str(body.get("email") or "").strip()
                or (_v.get("principal_id") or _v.get("user_id") or "")[:12]
                or ""
            )
            break
    if not account:
        account = "(未知)"

    tmp = _os.path.join(_os.environ.get("TEMP", "."), "grok_web_test_auth.json")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(auth, f, ensure_ascii=False, indent=2)
    except Exception as e:
        return jsonify({"ok": False, "error": f"写临时 auth 失败: {e}"})

    had_old = _os.path.isfile(AUTH_FILE)
    if had_old:
        _shutil.copy2(AUTH_FILE, BACKUP)

    def _run_grok(args, timeout_s: int):
        try:
            r = _subprocess.run(
                [GROK, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
            )
            return (r.stdout or "") + (r.stderr or ""), r.returncode
        except _subprocess.TimeoutExpired:
            return "", -9

    try:
        _shutil.copy2(tmp, AUTH_FILE)
        t0 = _time.time()
        models_out, _ = _run_grok(["models"], 60)
        reply_out, rc = _run_grok(["-p", message_text, "-m", model], 120)
        elapsed_s = round(_time.time() - t0, 1)
        ok = rc == 0 and bool((reply_out or "").strip())
        return jsonify({
            "ok": ok,
            "exit_code": rc,
            "elapsed_s": elapsed_s,
            "exchanged": exchange,
            "account": account,
            "models": models_out.strip()[:400],
            "reply": reply_out.strip()[-6000:],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"测试执行失败: {e}"})
    finally:
        try:
            if had_old:
                _shutil.copy2(BACKUP, AUTH_FILE)
        except Exception:
            pass


@app.post("/api/manual-code")
def api_manual_code():
    """手动模式：提交粘贴的验证码（写入 logs/manual_code.txt 供注册流程读取）；
    附带 email 时同时保存 MANUAL_EMAIL。"""
    body = request.get_json(silent=True) or {}
    code = str(body.get("code") or "").strip()
    email = str(body.get("email") or "").strip()
    if not code:
        return jsonify({"ok": False, "error": "验证码为空"})
    try:
        (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
        if email:
            # 多邮箱手动模式：写入该邮箱独立通道，避免并发抢码
            safe = re.sub(r"[^A-Za-z0-9._@-]", "_", email)
            cdir = BASE_DIR / "logs" / "manual_codes"
            cdir.mkdir(parents=True, exist_ok=True)
            (cdir / f"{safe}.txt").write_text(code, encoding="utf-8")
        else:
            (BASE_DIR / "logs" / "manual_code.txt").write_text(code, encoding="utf-8")
    except Exception as e:
        return jsonify({"ok": False, "error": f"写入验证码失败: {e}"}), 500
    msg = f"验证码已提交（{str(code)[:10]}…），等待注册流程读取"
    if email:
        msg = f"已写入邮箱 {email} 的通道；" + msg
    if email:
        try:
            values = {"MANUAL_EMAIL": email}
            write_env_file(values)
            apply_env_to_process(values)
        except Exception:
            pass
    return jsonify({"ok": True, "message": msg})


@app.post("/api/proxy/validate")
def proxy_validate():
    """
    仅校验代理格式（不发网）。
    body.proxies / GROK_PROXY_LIST / text：多行文本。
    """
    body = request.get_json(silent=True) or {}
    raw = ""
    if "proxies" in body:
        raw = str(body.get("proxies") or "")
    elif "GROK_PROXY_LIST" in body:
        raw = str(body.get("GROK_PROXY_LIST") or "")
    elif "text" in body:
        raw = str(body.get("text") or "")
    elif "GROK_PROXY" in body:
        raw = str(body.get("GROK_PROXY") or "")
    else:
        raw = (
            (os.environ.get("GROK_PROXY_LIST") or "").strip()
            or (read_env_file().get("GROK_PROXY_LIST") or "").strip()
            or (os.environ.get("GROK_PROXY") or "").strip()
        )
    lines = _split_proxy_lines(raw)
    try:
        from g.same_session_register import parse_proxy_spec
    except Exception as e:
        return jsonify({"ok": False, "message": f"parse_proxy_spec 不可用: {e}"}), 500
    items = []
    bad = 0
    for i, line in enumerate(lines, 1):
        parsed = parse_proxy_spec(line)
        ok = bool(parsed and (parsed.get("server") or parsed.get("server_url")))
        entry = {
            "index": i,
            "raw": line if len(line) <= 96 else (line[:48] + "…" + line[-20:]),
            "ok": ok,
        }
        if ok:
            entry["scheme"] = parsed.get("scheme") or ""
            entry["server"] = parsed.get("server") or ""
            if parsed.get("username"):
                entry["auth"] = True
        else:
            bad += 1
            entry["error"] = "格式无法解析"
        items.append(entry)
    return jsonify({
        "ok": bad == 0,
        "total": len(lines),
        "valid": len(lines) - bad,
        "invalid": bad,
        "items": items,
        "message": (
            f"全部 {len(lines)} 条格式正确"
            if lines and bad == 0
            else (f"{bad}/{len(lines)} 条格式错误" if lines else "无代理（将直连）")
        ),
    })


@app.post("/api/proxy/test")
def proxy_test():
    """
    测试注册代理：先出口 IP/区域，再 accounts.x.ai 连通性。
    body.GROK_PROXY / proxy：可传临时值；不传则用当前已保存/进程环境。
    body.GROK_PROXY_LIST / proxies：多条时测全部（或 body.index 指定第 N 条，1-based）。
    空字符串 = 直连探测。
    """
    body = request.get_json(silent=True) or {}
    # 多代理批量
    pool_raw = None
    if "GROK_PROXY_LIST" in body:
        pool_raw = str(body.get("GROK_PROXY_LIST") or "")
    elif "proxies" in body:
        pool_raw = str(body.get("proxies") or "")
    lines = _split_proxy_lines(pool_raw) if pool_raw is not None else []

    if "GROK_PROXY" in body:
        raw = str(body.get("GROK_PROXY") or "").strip()
    elif "proxy" in body:
        raw = str(body.get("proxy") or "").strip()
    elif lines:
        raw = lines[0]
    else:
        raw = (
            (os.environ.get("GROK_PROXY") or "").strip()
            or (read_env_file().get("GROK_PROXY") or "").strip()
        )
        if not raw:
            saved_pool = _split_proxy_lines(
                (os.environ.get("GROK_PROXY_LIST") or "")
                or (read_env_file().get("GROK_PROXY_LIST") or "")
            )
            if saved_pool:
                lines = saved_pool
                raw = lines[0]

    try:
        timeout = float(body.get("timeout") or 12)
    except (TypeError, ValueError):
        timeout = 12.0

    # 指定 index（1-based）或 test_all
    test_all = bool(body.get("test_all") or body.get("all"))
    idx = body.get("index")
    if lines and idx is not None and str(idx).strip() != "":
        try:
            i = int(idx)
            if 1 <= i <= len(lines):
                raw = lines[i - 1]
                lines = [raw]
                test_all = False
        except (TypeError, ValueError):
            pass

    if test_all and lines:
        results = []
        ok_n = 0
        for i, line in enumerate(lines, 1):
            r = _probe_register_proxy(line, timeout=timeout)
            r["index"] = i
            results.append(r)
            if r.get("ok"):
                ok_n += 1
        summary = {
            "ok": ok_n > 0,
            "total": len(lines),
            "ok_count": ok_n,
            "fail_count": len(lines) - ok_n,
            "results": results,
            "message": f"批量测试 {ok_n}/{len(lines)} 通",
            # 兼容单测字段：用第一条成功的，否则第一条
            **(next((x for x in results if x.get("ok")), results[0] if results else {})),
        }
        try:
            level = "success" if ok_n else "warn"
            logs.emit(f"代理批量测试: {summary['message']}", level)
        except Exception:
            pass
        code = 200 if ok_n else 502
        return jsonify(summary), code

    # 单条：先格式校验
    if raw:
        try:
            from g.same_session_register import parse_proxy_spec
            if not parse_proxy_spec(raw):
                return jsonify({
                    "ok": False,
                    "proxy": raw[:80],
                    "error": "代理格式无法解析",
                    "message": (
                        "格式错误。支持 host:port · http/socks5:// · "
                        "user:pass@host:port · host:port:user:pass"
                    ),
                }), 400
        except Exception:
            pass

    result = _probe_register_proxy(raw, timeout=timeout)
    try:
        level = "success" if result.get("ok") else "warn"
        logs.emit(f"代理测试: {result.get('message') or result.get('error')}", level)
    except Exception:
        pass
    code = 200 if result.get("ok") else 502
    return jsonify(result), code


@app.post("/api/upstream/test")
def upstream_test():
    """测试 sub2api HTTP 登录与 Grok 分组（可用临时参数覆盖已保存配置）。"""
    body = request.get_json(silent=True) or {}
    base = body.get("SUB2API_URL") or body.get("UPSTREAM_URL") or body.get("url")
    admin_email = body.get("UPSTREAM_ADMIN_EMAIL") or body.get("email")
    pwd = body.get("UPSTREAM_ADMIN_PASSWORD") or body.get("password")
    group_id = body.get("SUB2API_GROK_GROUP_ID") or body.get("group_id")
    group_name = body.get("SUB2API_GROK_GROUP_NAME") or body.get("group_name")
    # 空字符串表示“用已保存值”
    if base is not None and str(base).strip() == "":
        base = None
    if admin_email is not None and str(admin_email).strip() == "":
        admin_email = None
    if pwd is not None and str(pwd).strip() == "":
        pwd = None
    if group_id is not None and str(group_id).strip() == "":
        group_id = None
    if group_name is not None and str(group_name).strip() == "":
        group_name = None
    result = test_upstream_connectivity(
        base_url=str(base).strip() if base is not None else None,
        password=str(pwd) if pwd is not None else None,
        email=str(admin_email).strip() if admin_email is not None else None,
        group_id=str(group_id).strip() if group_id is not None else None,
        group_name=str(group_name).strip() if group_name is not None else None,
    )
    code = 200 if result.get("ok") else 502
    return jsonify(result), code


def _safe_keys_file(name: str) -> Path | None:
    """仅允许读取 keys/ 下的 .txt，防止路径穿越。"""
    raw = (name or "").strip().replace("\\", "/")
    if not raw or raw.startswith("/") or ".." in raw.split("/"):
        return None
    # 允许传 "keys/xxx.txt" 或 "xxx.txt"
    if raw.lower().startswith("keys/"):
        raw = raw[5:]
    if not raw.lower().endswith(".txt"):
        return None
    keys_dir = (BASE_DIR / "keys").resolve()
    path = (keys_dir / Path(raw).name).resolve()
    try:
        path.relative_to(keys_dir)
    except ValueError:
        return None
    if not path.is_file():
        return None
    return path


@app.get("/api/keys")
def list_key_files():
    """List downloadable result files without exposing anything outside keys/."""
    keys_dir = BASE_DIR / "keys"
    if not keys_dir.is_dir():
        return jsonify({"files": []})

    files = []
    for path in keys_dir.iterdir():
        if not path.is_file() or path.suffix.lower() not in (".txt", ".csv"):
            continue
        is_credentials = path.name.lower().endswith("_credentials.csv")
        if path.suffix.lower() == ".csv" and not is_credentials:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            count = len([line for line in lines if line.strip()])
            if is_credentials and lines and lines[0].strip().lower() == "email,password":
                count -= 1
            stat = path.stat()
        except OSError:
            continue
        files.append({
            "name": path.name,
            "path": f"keys/{path.name}",
            "size": stat.st_size,
            "count": max(0, count),
            "kind": "credentials" if is_credentials else "sso",
            "modified": int(stat.st_mtime),
        })
    files.sort(key=lambda item: item["modified"], reverse=True)
    return jsonify({"files": files})


def _read_sso_file_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _mark_recent_imported(selected: list[dict] | None, result: dict) -> None:
    """按导入结果标记 recent_success 中的项为已导入。"""
    if not (result.get("ok") or (result.get("success") or 0) > 0):
        return
    ok_emails = set()
    ok_sso_hints = set()
    for row in result.get("results") or []:
        if row.get("status") != "ok":
            continue
        if row.get("email"):
            ok_emails.add(str(row["email"]).lower())
        hint = row.get("sso_hint") or ""
        if hint:
            ok_sso_hints.add(hint)
    selected = selected or []
    for it in engine.recent_success:
        if not it.get("sso"):
            continue
        email = (it.get("email") or "").lower()
        sso = it.get("sso") or ""
        sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso
        if email and email in ok_emails:
            it["imported"] = True
            it["auth_token"] = None
        elif sso_hint and sso_hint in ok_sso_hints:
            it["imported"] = True
            it["auth_token"] = None
        elif result.get("ok") and selected and any(
            it is x or it.get("id") == x.get("id") for x in selected
        ):
            it["imported"] = True
            it["auth_token"] = None


@app.post("/api/upstream/import")
def upstream_import():
    """将最近成功的 SSO / keys 文件导入 sub2api grok 分组。"""
    body = request.get_json(silent=True) or {}
    merge = body.get("merge", True)
    # 本机 device flow 后写 token：固定串行，忽略客户端并发参数
    try:
        max_workers = int(body.get("max_workers", 1))
    except (TypeError, ValueError):
        max_workers = 1
    max_workers = 1

    # 支持：keys 文件 / 指定 id / 指定 sso 原文 / 当前 output_file / 全部未导入
    ids = body.get("ids")
    if ids is not None and not isinstance(ids, list):
        return jsonify({"ok": False, "message": "ids 必须是数组"}), 400

    raw_ssos = body.get("sso_cookies") or body.get("ssos")
    only_pending = bool(body.get("only_pending", True))
    import_all = bool(body.get("all", False))
    file_name = body.get("file") or body.get("from_file") or body.get("key_file")
    use_output_file = bool(body.get("from_output", False))

    items = list(engine.recent_success)
    selected: list[dict] = []
    sso_lines: list[str] = []
    source = "recent_success"

    if raw_ssos and isinstance(raw_ssos, list) and raw_ssos:
        # 直接导入调用方提供的 SSO 行（无注册缓存 token，走 device flow）
        for line in raw_ssos:
            s = str(line or "").strip()
            if s:
                sso_lines.append(s)
        if not sso_lines:
            return jsonify({"ok": False, "message": "sso_cookies 为空"}), 400
        source = "sso_cookies"
        result = import_sso_to_upstream(
            sso_lines=sso_lines, merge=merge, max_workers=max_workers
        )
        _mark_recent_imported(None, result)
        level = "success" if result.get("ok") else ("warn" if (result.get("success") or 0) > 0 else "error")
        logs.emit(f"sub2api 导入: {result.get('message')}（提交 {len(sso_lines)} 条 · {source}）", level)
        code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
        result["submitted"] = len(sso_lines)
        result["source"] = source
        result["recent_success"] = engine.get_status().get("recent_success", [])
        return jsonify(result), code

    # 从 keys 文件或当前任务 output_file 全量导入（不受 recent_success 截断影响）
    file_path: Path | None = None
    if file_name:
        file_path = _safe_keys_file(str(file_name))
        if not file_path:
            return jsonify({"ok": False, "message": f"无效或不存在的 keys 文件: {file_name}"}), 400
        source = f"file:{file_path.name}"
    elif use_output_file and engine.output_file:
        candidate = Path(engine.output_file)
        if not candidate.is_absolute():
            candidate = BASE_DIR / candidate
        if candidate.is_file():
            file_path = candidate
            source = f"output:{candidate.name}"

    if file_path is not None:
        sso_lines = _read_sso_file_lines(file_path)
        if not sso_lines:
            return jsonify({"ok": False, "message": f"文件无有效 SSO: {file_path.name}"}), 400
        # 有缓存 token 的项尽量带上（同 sso 匹配），加速导入
        token_by_sso = {
            (it.get("sso") or "").strip(): it.get("auth_token")
            for it in items
            if it.get("sso") and isinstance(it.get("auth_token"), dict)
        }
        accounts = []
        for email, sso in _parse_sso_import_lines(sso_lines):
            sso = (sso or "").strip()
            if not sso:
                continue
            accounts.append(
                {
                    "email": email,
                    "sso": sso,
                    "auth_token": token_by_sso.get(sso),
                }
            )
        result = import_sso_to_upstream(
            accounts=accounts, merge=merge, max_workers=max_workers
        )
        _mark_recent_imported(None, result)
        level = "success" if result.get("ok") else ("warn" if (result.get("success") or 0) > 0 else "error")
        logs.emit(
            f"sub2api 导入: {result.get('message')}（提交 {len(accounts)} 条 · {source}）",
            level,
        )
        code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
        result["submitted"] = len(accounts)
        result["source"] = source
        result["file"] = file_path.name
        result["recent_success"] = engine.get_status().get("recent_success", [])
        return jsonify(result), code

    if ids:
        id_set = {str(x) for x in ids}
        for it in items:
            if str(it.get("id") or "") in id_set and it.get("sso"):
                selected.append(it)
    elif import_all:
        # 优先：内存未导入项；若为空且有 output_file，回退读文件（防重启/截断丢号）
        for it in items:
            if not it.get("sso"):
                continue
            if only_pending and it.get("imported"):
                continue
            selected.append(it)
        if not selected and engine.output_file:
            candidate = Path(engine.output_file)
            if not candidate.is_absolute():
                candidate = BASE_DIR / candidate
            if candidate.is_file():
                sso_lines = _read_sso_file_lines(candidate)
                if sso_lines:
                    source = f"output:{candidate.name}"
                    result = import_sso_to_upstream(
                        sso_lines=sso_lines, merge=merge, max_workers=max_workers
                    )
                    _mark_recent_imported(None, result)
                    level = (
                        "success"
                        if result.get("ok")
                        else ("warn" if (result.get("success") or 0) > 0 else "error")
                    )
                    logs.emit(
                        f"sub2api 导入: {result.get('message')}（提交 {len(sso_lines)} 条 · {source}）",
                        level,
                    )
                    code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
                    result["submitted"] = len(sso_lines)
                    result["source"] = source
                    result["file"] = candidate.name
                    result["recent_success"] = engine.get_status().get("recent_success", [])
                    return jsonify(result), code
    else:
        # 默认：全部未导入
        for it in items:
            if it.get("sso") and not it.get("imported"):
                selected.append(it)

    if not selected:
        return jsonify({
            "ok": False,
            "message": "没有可导入的成功账号（请先注册，或选择 keys 文件导入）",
        }), 400

    # 去重 SSO，并带上注册时缓存的 auth_token（有则导入秒级直写）
    seen = set()
    accounts = []
    for it in selected:
        sso = (it.get("sso") or "").strip()
        if not sso or sso in seen:
            continue
        seen.add(sso)
        email = (it.get("email") or "").strip()
        token = it.get("auth_token")
        accounts.append(
            {
                "email": email,
                "sso": sso,
                "auth_token": token if isinstance(token, dict) else None,
            }
        )

    result = import_sso_to_upstream(
        accounts=accounts, merge=merge, max_workers=max_workers
    )
    _mark_recent_imported(selected, result)

    level = "success" if result.get("ok") else ("warn" if (result.get("success") or 0) > 0 else "error")
    logs.emit(f"sub2api 导入: {result.get('message')}（提交 {len(accounts)} 条 · {source}）", level)
    code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
    result["submitted"] = len(accounts)
    result["source"] = source
    # 与 /api/status 一致：不回传完整 sso
    result["recent_success"] = engine.get_status().get("recent_success", [])
    return jsonify(result), code


@app.get("/keys/<path:filename>")
def download_key(filename):
    return send_from_directory(BASE_DIR / "keys", filename, as_attachment=True)


def main():
    cfg = read_env_file()
    apply_env_to_process(cfg)
    host = cfg.get("UI_HOST") or os.getenv("UI_HOST", "127.0.0.1")
    port = int(cfg.get("UI_PORT") or os.getenv("UI_PORT", "3333"))
    print("=" * 60)
    print("Grok 注册机 Web 控制台")
    print(f"打开浏览器: http://{host}:{port}")
    print("=" * 60)
    logs.emit("Web 控制台已启动", "success")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
