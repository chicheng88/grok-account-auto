# -*- coding: utf-8 -*-
"""
同会话协议注册（主路径，默认直连、不用代理）

根因（旧路径必 deny / 无 sso）:
1. 拆会话: Chrome mint castle → 拷到 curl_cffi signup
   → BOT_FLAG_SOURCE_CASTLE policy=deny
2. page.request 发码: Playwright 独立 TLS ≠ 页面 Chrome → CF 403
3. set-cookie 截断: RSC `18:T9d5,<url>` 必须按 hex 长度取完整 URL
   → 短正则/独立 curl 无注册会话 → 400/auth-error，jar 无 sso

正确路径（已验证能拿 clean sso）:
  同一 Chrome persistent context:
    sign-up 加载 → 等 React 水合
    → page.evaluate mint castle（不点 UI、不填表单）
    → 页内 fetch(gRPC 发码/验码)
    → 页内 fetch(signup + 同页 castle)
    → context.request 跟完整 set-cookie 链落 sso
  禁止：点「Sign up with email」、type 邮箱、鼠标乱点。
  成功门槛在注册机侧：risk 未标记才计 success。
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import shutil
import string
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .castle_service import (
    MIN_CASTLE_LEN,
    SITE,
    _MINT_JS,
    is_castle_token_usable,
    mint_js_args,
    new_conversion_id,
)

_BASE = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE_ROOT = _BASE / "logs" / "same_session_profiles"

# 日志里别再喷 JWT / Playwright Call log
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}"
)
_URL_QUERY_RE = re.compile(r"(https?://[^\s?'\"]+\?)[^\s'\"]+")

# ---------- Camoufox 线程本地池（每 worker 线程自用）----------
# Playwright Sync API 绑定 greenlet + 线程内 event loop：
# 1) 禁止跨线程复用 browser
# 2) **同一线程同一时刻只能有 1 个存活的 Playwright Sync 驱动**
#    若旧 Camoufox 还在池里又冷启第二个 →
#    「Sync API inside the asyncio loop」——这就是成功号之后下一号炸掉的根因。
#
# 打散：限次复用 + 概率换新；换新前必须先关干净旧实例，再 Camoufox()。
_CAMOUFOX_POOL_LOCK = threading.Lock()
# tid -> 至多 1 条: {"cm","browser","is_browser","uses","owner_tid","fp_os","locale","proxy","gen"}
_CAMOUFOX_POOLS: dict[int, Optional[dict[str, Any]]] = {}
_CAMOUFOX_GEN: dict[int, int] = {}


def _browser_pool_enabled() -> bool:
    raw = (os.getenv("GROK_SAME_SESSION_BROWSER_POOL") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


def _pool_max_uses() -> int:
    """单 browser 最多服务几号；默认 1（每号冷启，指纹更散）。"""
    try:
        n = int(
            (
                os.getenv("GROK_SAME_SESSION_BROWSER_POOL_MAX_USES")
                or os.getenv("GROK_SS_POOL_MAX_USES")
                or "1"
            ).strip()
            or "1"
        )
    except ValueError:
        n = 1
    return max(1, min(8, n))


def _pool_force_cold_prob() -> float:
    """强制换新概率（关旧再启）。默认 0.65，配合限次=1 基本每号新浏览器。"""
    raw = (
        os.getenv("GROK_SAME_SESSION_BROWSER_POOL_COLD_PROB")
        or os.getenv("GROK_SS_POOL_COLD_PROB")
        or "0.65"
    ).strip()
    try:
        p = float(raw)
    except ValueError:
        p = 0.65
    return max(0.0, min(1.0, p))


def _clear_thread_event_loop(*, force: bool = False) -> None:
    """
    Playwright Sync 退出后，线程上可能仍挂着 loop / _running_loop。
    清掉，避免下一次 Camoufox() 误判「inside asyncio loop」。

    force=True：连「仍标记 running」的残留也清（greenlet 异常退出常见）。
    会动 asyncio 私有 _set_running_loop，仅用于本线程冷启抢救。
    """
    try:
        import asyncio
        from asyncio import events as aio_events

        # 1) 先摘掉 thread-local running 标记（Playwright 用 get_running_loop 判死刑）
        if force:
            try:
                setter = getattr(aio_events, "_set_running_loop", None)
                if callable(setter):
                    setter(None)
            except Exception:
                pass

        loop = None
        try:
            loop = asyncio.get_event_loop_policy().get_event_loop()
        except RuntimeError:
            loop = None
        except Exception:
            loop = None

        if loop is not None:
            running = False
            try:
                running = bool(loop.is_running())
            except Exception:
                running = False
            if running and force:
                try:
                    loop.stop()
                except Exception:
                    pass
            if not running or force:
                try:
                    if not loop.is_closed():
                        # running+force 时 close 可能抛，忽略
                        loop.close()
                except Exception:
                    pass

        try:
            asyncio.set_event_loop(None)
        except Exception:
            pass

        # 2) 再装一个全新 loop 立刻卸掉，打断策略缓存
        try:
            fresh = asyncio.new_event_loop()
            asyncio.set_event_loop(fresh)
            try:
                fresh.close()
            except Exception:
                pass
            asyncio.set_event_loop(None)
        except Exception:
            try:
                asyncio.set_event_loop(None)
            except Exception:
                pass

        if force:
            try:
                setter = getattr(aio_events, "_set_running_loop", None)
                if callable(setter):
                    setter(None)
            except Exception:
                pass
    except Exception:
        pass


def _close_pool_entry(ent: Optional[dict[str, Any]], log_fn=None, reason: str = "") -> None:
    if not ent:
        return
    cm = ent.get("cm")
    if cm is None:
        return
    try:
        cm.__exit__(None, None, None)
    except Exception as e:
        if log_fn:
            try:
                log_fn(f"camoufox 关闭异常 · {_compact_log(e, 60)}")
            except Exception:
                pass
    finally:
        # 关闭驱动后必须 force 清（含 _running_loop），否则下号 Sync API 必炸
        _clear_thread_event_loop(force=True)
        if log_fn and reason:
            try:
                # 文案避免依赖控制台代码页；ASCII 关键词方便 grep
                log_fn(f"camoufox closed · {reason}")
            except Exception:
                pass


def _get_thread_ent() -> Optional[dict[str, Any]]:
    tid = threading.get_ident()
    with _CAMOUFOX_POOL_LOCK:
        return _CAMOUFOX_POOLS.get(tid)


def _set_thread_ent(ent: Optional[dict[str, Any]]) -> None:
    tid = threading.get_ident()
    with _CAMOUFOX_POOL_LOCK:
        if ent is None:
            _CAMOUFOX_POOLS.pop(tid, None)
        else:
            _CAMOUFOX_POOLS[tid] = ent


def _drop_thread_pool(log_fn=None, reason: str = "") -> None:
    """关掉本线程唯一实例（冷启前必调）。"""
    ent = _get_thread_ent()
    _set_thread_ent(None)
    _close_pool_entry(ent, log_fn=log_fn, reason=reason or "换新前清理")


def shutdown_camoufox_pool() -> None:
    """进程退出 / 批末释放所有线程池内的 Camoufox。"""
    with _CAMOUFOX_POOL_LOCK:
        items = [e for e in _CAMOUFOX_POOLS.values() if e]
        _CAMOUFOX_POOLS.clear()
        _CAMOUFOX_GEN.clear()
    for ent in items:
        _close_pool_entry(ent, reason="")


def _next_gen(tid: int) -> int:
    with _CAMOUFOX_POOL_LOCK:
        g = int(_CAMOUFOX_GEN.get(tid, 0) or 0) + 1
        _CAMOUFOX_GEN[tid] = g
        return g


def _acquire_camoufox_pooled(
    *,
    fp_os_val: str,
    locale: str,
    humanize_val: bool,
    vp: dict[str, int],
    pw_proxy: Optional[dict[str, str]],
    timezone_id: str,
    log_fn,
    accept_language: Optional[str] = None,
    languages: Optional[list[str]] = None,
    device_fp: Optional[dict[str, Any]] = None,
) -> tuple[Any, Any, Any, bool, float]:
    """
    返回 (camoufox_cm_or_None, ctx, page, from_pool, launch_s)
    from_pool=True：只关 context，browser 留在本线程池。

    硬规则：本线程同时最多 1 个存活 Camoufox/Playwright Sync。
    需要换新时先 __exit__ 旧的并清 event loop，再冷启。
    语言跟随 locale：Accept-Language + navigator.languages。
    device_fp：WebGL/屏幕/CPU/媒体等设备上下文（一号一换）。
    """
    proxy_server = (pw_proxy or {}).get("server") if pw_proxy else None
    proxy_s = (proxy_server or "direct").strip()
    lang_pack = locale_language_pack(locale)
    locale = lang_pack["locale"]
    al_header = (accept_language or lang_pack["accept_language"]).strip()
    nav_langs = list(languages or lang_pack["languages"])
    loc_main = locale.lower()
    tid = threading.get_ident()
    t_launch = time.time()
    max_uses = _pool_max_uses()
    cold_prob = _pool_force_cold_prob()
    pool_on = _browser_pool_enabled()

    # 设备指纹：未传则按 OS+viewport 现生成（保证 Camoufox 总有富上下文）
    if not device_fp:
        device_fp = build_device_fingerprint(fp_os_val, viewport=vp)
    else:
        # 外部传入时仍保证 viewport 一致
        if vp and not (device_fp.get("viewport") or {}).get("width"):
            device_fp = dict(device_fp)
            device_fp["viewport"] = dict(vp)
    vp = dict(device_fp.get("viewport") or vp or _rand_viewport())
    device_fp = dict(device_fp)
    device_fp["viewport"] = vp
    device_fp["fp_os"] = (
        "macos"
        if str(fp_os_val).lower() in ("mac", "macos", "osx", "darwin")
        else "windows"
    )
    webgl_tag = (
        f"{str(device_fp.get('webgl_vendor') or '')[:18]}|"
        f"{str(device_fp.get('webgl_renderer') or '')[:28]}"
    )

    ent = _get_thread_ent()

    # 池坏/超次/指纹 OS 或代理变了 → 必须关旧（os/proxy 是 launch 级，不能靠 new_context）
    # WebGL/screen 也是 launch 级，一号一换设备指纹时直接冷启
    need_drop = False
    drop_reason = ""
    if ent is not None:
        if int(ent.get("owner_tid") or 0) != tid:
            need_drop, drop_reason = True, "owner 不匹配"
        elif int(ent.get("uses") or 0) >= max_uses:
            need_drop, drop_reason = (
                True,
                f"max_uses hit uses={ent.get('uses')}/{max_uses}",
            )
        elif str(ent.get("fp_os") or "") != fp_os_val:
            need_drop, drop_reason = (
                True,
                f"os change {ent.get('fp_os')}->{fp_os_val}",
            )
        elif str(ent.get("proxy") or "direct").strip() != proxy_s:
            need_drop, drop_reason = True, "proxy change"
        # launch 级 locale 与本号不一致 → 冷启（Camoufox 进程语言）
        elif str(ent.get("locale") or "").lower() != loc_main:
            need_drop, drop_reason = (
                True,
                f"locale change {ent.get('locale')}->{locale}",
            )
        elif str(ent.get("webgl_tag") or "") != webgl_tag:
            need_drop, drop_reason = True, "device/webgl change"
        elif not ent.get("is_browser") or ent.get("browser") is None:
            need_drop, drop_reason = True, "browser invalid"

    force_cold = (not pool_on) or (random.random() < cold_prob)
    if force_cold and ent is not None and pool_on:
        need_drop = True
        drop_reason = drop_reason or f"强制打散 p={cold_prob:.2f}"

    if need_drop:
        _drop_thread_pool(log_fn, reason=drop_reason)
        ent = None

    ctx_kw = _context_locale_kwargs(
        locale, timezone_id, vp, accept_language=al_header
    )

    # —— 尝试复用（仅 new_context：locale/timezone/viewport/语言头 可每号不同）——
    if pool_on and ent is not None and not force_cold:
        browser = ent.get("browser")
        try:
            if ent.get("is_browser") and hasattr(browser, "new_context"):
                ctx = browser.new_context(**ctx_kw)
                page = ctx.new_page()
                _apply_navigator_languages(page, nav_langs, lang_pack["lang"])
                _apply_device_context(page, device_fp)
                ent["uses"] = int(ent.get("uses") or 0) + 1
                ent["locale"] = loc_main
                uses_now = int(ent["uses"])
                launch_s = round(time.time() - t_launch, 2)
                log_fn(
                    f"camoufox 池复用 · tid={tid} · gen={ent.get('gen')} · "
                    f"{fp_os_val}/{locale} · al={al_header[:32]} · "
                    f"#{uses_now}/{max_uses} · {launch_s}s"
                )
                return None, ctx, page, True, launch_s
        except Exception as e:
            log_fn(f"camoufox 池失效 · {_compact_log(e, 80)}")
            _drop_thread_pool(log_fn, reason="复用失败")
            ent = None

    # —— 冷启：先确保本线程没有残留 Sync 驱动 ——
    if _get_thread_ent() is not None:
        _drop_thread_pool(log_fn, reason="冷启前残留清理")
    else:
        # 即便池空，也可能有脏 loop（池线程复用）
        _clear_thread_event_loop(force=True)

    from camoufox.sync_api import Camoufox

    gen = _next_gen(tid)
    scr = device_fp.get("screen") or {}
    log_fn(
        f"启动 camoufox · tid={tid} · gen={gen} · {fp_os_val}/{locale} · "
        f"lang={lang_pack['lang']} · al={al_header[:40]} · "
        f"vp={int(vp['width'])}x{int(vp['height'])} · "
        f"screen={int(scr.get('width') or 0)}x{int(scr.get('height') or 0)} · "
        f"dpr={device_fp.get('device_pixel_ratio')} · "
        f"hw={device_fp.get('hardware_concurrency')} · "
        f"gpu={str(device_fp.get('webgl_renderer') or '')[:36]}"
    )
    fox_kwargs: dict[str, Any] = {
        "headless": True,
        "os": fp_os_val,
        "locale": locale,
        "humanize": bool(humanize_val),
        "window": (int(vp["width"]), int(vp["height"])),
        "block_webrtc": True,
        "block_webgl": False,
    }
    # 富设备指纹：WebGL / screen / hardware / media / canvas / audio
    try:
        fox_kwargs.update(device_fp_camoufox_kwargs(device_fp))
    except Exception as _df_err:
        try:
            log_fn(f"device_fp 映射跳过 · {_compact_log(_df_err, 60)}")
        except Exception:
            pass
    # 部分 camoufox 版本支持 languages；不支持则忽略
    try:
        fox_kwargs["locale"] = locale
    except Exception:
        pass
    if pw_proxy:
        fox_kwargs["proxy"] = pw_proxy
        # geoip=True：Camoufox 经代理查出口 IP，对齐 locale/时区，并消掉 LeakWarning。
        # 远程代理（1024 等）常「Failed to get IP」→ 冷启失败，故：
        #   本机 127.0.0.1/localhost 默认开；其它出口默认关。
        # 强制：GROK_CAMOUFOX_GEOIP=1/0
        _geo_env = (os.getenv("GROK_CAMOUFOX_GEOIP") or "").strip().lower()
        if _geo_env in ("1", "true", "yes", "on"):
            fox_kwargs["geoip"] = True
        elif _geo_env in ("0", "false", "no", "off"):
            fox_kwargs["geoip"] = False
        else:
            _ps = str(
                (pw_proxy.get("server") if isinstance(pw_proxy, dict) else pw_proxy) or ""
            ).lower()
            _local = any(
                h in _ps
                for h in ("127.0.0.1", "localhost", "[::1]", "0.0.0.0")
            )
            fox_kwargs["geoip"] = bool(_local)

    t_launch = time.time()
    last_err: Optional[BaseException] = None
    camoufox_cm = None
    camoufox_browser = None

    def _is_sync_loop_err(err: BaseException) -> bool:
        msg = str(err or "")
        return (
            "asyncio loop" in msg
            or "Async API" in msg
            or "Sync API" in msg
            or "Playwright Sync" in msg
        )

    def _is_proxy_geoip_err(err: BaseException) -> bool:
        msg = str(err or "").lower()
        return (
            "failed to get ip" in msg
            or "get ip address" in msg
            or "geoip" in msg
        )

    def _try_enter_once() -> tuple[Any, Any]:
        """
        在「干净」状态下进 Camoufox。若本线程 get_running_loop 仍活着，
        Playwright Sync 会直接拒绝——先 force 清再进。
        """
        import asyncio

        _clear_thread_event_loop(force=True)
        # 探测：若仍能 get_running_loop，再清一轮
        for _ in range(3):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                break
            _clear_thread_event_loop(force=True)
            time.sleep(0.05)
        else:
            # 仍 running：最后手段再清
            _clear_thread_event_loop(force=True)
        import warnings

        # 有代理但未开 geoip 时 Camoufox 喷 LeakWarning(RuntimeWarning) 到 stderr；
        # PowerShell 会当 NativeCommandError 再乱码。本机 7897 已默认 geoip，
        # 远程代理关 geoip 时也压掉这条提示（locale/tz 我们自己注入）。
        try:
            from camoufox.warnings import LeakWarning as _CamoufoxLeakWarning
        except Exception:
            _CamoufoxLeakWarning = RuntimeWarning  # type: ignore[misc, assignment]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=_CamoufoxLeakWarning)
            warnings.filterwarnings(
                "ignore",
                message=r".*geoip=True.*",
                category=Warning,
            )
            cm = Camoufox(**fox_kwargs)
            browser = cm.__enter__()
        return cm, browser

    # 冷启：最多 5 次，全部 force 清 loop（池复用线程必脏）
    _clear_thread_event_loop(force=True)
    for attempt in range(1, 6):
        try:
            if _get_thread_ent() is not None:
                _drop_thread_pool(log_fn, reason="启动前仍有残留池")
                _clear_thread_event_loop(force=True)
            camoufox_cm, camoufox_browser = _try_enter_once()
            last_err = None
            break
        except BaseException as e:
            last_err = e
            if _is_sync_loop_err(e):
                log_fn(
                    f"camoufox Sync/loop 冲突 try#{attempt}/5 · force清loop · "
                    f"{_compact_log(e, 80)}"
                )
                try:
                    if camoufox_cm is not None:
                        camoufox_cm.__exit__(None, None, None)
                except Exception:
                    pass
                camoufox_cm = None
                camoufox_browser = None
                _drop_thread_pool(log_fn, reason="loop冲突回收")
                _clear_thread_event_loop(force=True)
                time.sleep(0.25 * attempt)
                continue
            # WebGL pair 不在 camoufox db → 回退 M1 / 去掉 webgl_config 再启
            _em = str(e or "").lower()
            if "no webgl data" in _em or "webgl data found" in _em:
                log_fn(
                    f"camoufox WebGL 库无此卡 try#{attempt}/5 · "
                    f"回退 Apple M1 · {_compact_log(e, 100)}"
                )
                fox_kwargs["webgl_config"] = (
                    "Apple",
                    "Apple M1, or similar",
                )
                # 若仍失败，下一轮可 pop；本轮先钉死 M1
                if attempt >= 3:
                    fox_kwargs.pop("webgl_config", None)
                try:
                    if camoufox_cm is not None:
                        camoufox_cm.__exit__(None, None, None)
                except Exception:
                    pass
                camoufox_cm = None
                camoufox_browser = None
                _drop_thread_pool(log_fn, reason="webgl库无")
                _clear_thread_event_loop(force=True)
                time.sleep(0.2 * attempt)
                continue
            if _is_proxy_geoip_err(e) and fox_kwargs.get("geoip"):
                # 远程代理 geoip 探测失败：关 geoip 再试（locale/tz 仍用注入值）
                log_fn(
                    f"camoufox geoip 失败 try#{attempt}/5 · 关 geoip 重试 · "
                    f"{_compact_log(e, 80)}"
                )
                fox_kwargs["geoip"] = False
                try:
                    if camoufox_cm is not None:
                        camoufox_cm.__exit__(None, None, None)
                except Exception:
                    pass
                camoufox_cm = None
                camoufox_browser = None
                _drop_thread_pool(log_fn, reason="geoip失败")
                _clear_thread_event_loop(force=True)
                time.sleep(0.3 * attempt)
                continue
            if _is_proxy_geoip_err(e) and attempt < 5:
                log_fn(
                    f"camoufox 代理/IP 探测失败 try#{attempt}/5 · "
                    f"{_compact_log(e, 80)}"
                )
                try:
                    if camoufox_cm is not None:
                        camoufox_cm.__exit__(None, None, None)
                except Exception:
                    pass
                camoufox_cm = None
                camoufox_browser = None
                _drop_thread_pool(log_fn, reason="代理IP失败")
                _clear_thread_event_loop(force=True)
                time.sleep(0.5 * attempt)
                continue
            # 非可恢复错误直接抛
            try:
                if camoufox_cm is not None:
                    camoufox_cm.__exit__(None, None, None)
            except Exception:
                pass
            raise
    if last_err is not None or camoufox_cm is None or camoufox_browser is None:
        _clear_thread_event_loop(force=True)
        raise last_err or RuntimeError("camoufox 启动失败")

    is_browser = hasattr(camoufox_browser, "new_context")
    if is_browser:
        ctx = camoufox_browser.new_context(**ctx_kw)
        page = ctx.new_page()
        _apply_navigator_languages(page, nav_langs, lang_pack["lang"])
        _apply_device_context(page, device_fp)
    else:
        ctx = camoufox_browser
        page = ctx.new_page()
        try:
            ctx.set_extra_http_headers({"Accept-Language": al_header})
        except Exception:
            pass
        _apply_navigator_languages(page, nav_langs, lang_pack["lang"])
        _apply_device_context(page, device_fp)
    launch_s = round(time.time() - t_launch, 2)
    log_fn(f"camoufox 就绪 · tid={tid} · gen={gen} · {launch_s}s")

    if pool_on and is_browser:
        _set_thread_ent(
            {
                "cm": camoufox_cm,
                "browser": camoufox_browser,
                "is_browser": True,
                "uses": 1,
                "owner_tid": tid,
                "fp_os": fp_os_val,
                "locale": loc_main,
                "proxy": proxy_s,
                "webgl_tag": webgl_tag,
                "gen": gen,
                "born": time.time(),
            }
        )
        # 池接管生命周期；本号只关 ctx
        return None, ctx, page, True, launch_s

    return camoufox_cm, ctx, page, False, launch_s


def _compact_log(msg: Any, max_len: int = 160) -> str:
    """把异常/日志压成一行短文案，去掉 Call log、JWT、超长 query。"""
    s = str(msg or "")
    if "Call log:" in s:
        s = s.split("Call log:", 1)[0]
    # Playwright 常把整段 request dump 拼进 message
    for sep in ("\n", " - → ", " - user-agent:", " - accept:"):
        if sep in s:
            s = s.split(sep, 1)[0]
    s = _JWT_RE.sub("[JWT]", s)
    s = _URL_QUERY_RE.sub(r"\1…", s)
    s = re.sub(r"\s+", " ", s).strip()
    # 常见代理超时：只留关键
    m = re.search(
        r"connect ETIMEDOUT\s+(\d+\.\d+\.\d+\.\d+:\d+)", s, re.I
    )
    if m:
        s = f"connect ETIMEDOUT {m.group(1)} (proxy?)"
    elif "ETIMEDOUT" in s.upper():
        s = "connect ETIMEDOUT"
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def _default_proxy_scheme() -> str:
    """
    无 scheme 的 host:port:user:pass 默认协议。
    1024proxy 等 socket 池是 socks5；本机 mixed 口多为 http。
    覆盖：GROK_PROXY_SCHEME=socks5|http
    """
    raw = (os.getenv("GROK_PROXY_SCHEME") or os.getenv("STANDALONE_PROXY_SCHEME") or "").strip().lower()
    if raw in ("socks5", "socks5h", "socks4", "http", "https"):
        return "socks5h" if raw == "socks5" else raw
    # 启发式：文件/环境没写时，远程商用口默认 socks5h（DNS 走代理）
    return "http"


def parse_proxy_spec(spec: str) -> Optional[dict[str, str]]:
    """
    解析代理配置，支持:
      host:port:user:pass
      user:pass@host:port
      http://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port
    返回 Playwright proxy dict: {server, username?, password?}
    以及 server_url（带鉴权的完整 URL，给 curl 用）。
    无 scheme 时：GROK_PROXY_SCHEME / STANDALONE_PROXY_SCHEME（默认 http；
    socket 池写入时会带 socks5h:// 前缀）。
    """
    s = (spec or "").strip()
    if not s:
        return None
    default_scheme = _default_proxy_scheme()

    def _pack(scheme: str, host: str, port: str, user: str = "", pw: str = "") -> dict[str, str]:
        from urllib.parse import quote

        sch = (scheme or default_scheme or "http").lower()
        if sch == "socks5":
            sch = "socks5h"  # 远程解析走代理，避 DNS 泄露/污染
        server = f"{sch}://{host}:{port}"
        out: dict[str, str] = {"server": server, "scheme": sch}
        if user:
            out["username"] = user
            out["password"] = pw or ""
            out["server_url"] = (
                f"{sch}://{quote(user, safe='')}:{quote(pw or '', safe='')}@"
                f"{host}:{port}"
            )
        else:
            out["server_url"] = server
        return out

    # 完整 URL
    if "://" in s:
        # http://user:pass@host:port
        m = re.match(
            r"^(?P<scheme>https?|socks5h?|socks4)://"
            r"(?:(?P<user>[^:@/]+):(?P<pass>[^@/]+)@)?"
            r"(?P<host>[^:/]+):(?P<port>\d+)/?$",
            s,
            re.I,
        )
        if not m:
            # 无端口也接受
            return {"server": s, "server_url": s}
        return _pack(
            m.group("scheme"),
            m.group("host"),
            m.group("port"),
            m.group("user") or "",
            m.group("pass") or "",
        )

    # user:pass@host:port
    if "@" in s:
        cred, hostport = s.rsplit("@", 1)
        if ":" in cred and ":" in hostport:
            user, pw = cred.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            return _pack(default_scheme, host, port, user, pw)

    # host:port:user:pass  （user 可能含冒号以外字符，port 是数字段）
    parts = s.split(":")
    if len(parts) >= 4:
        host = parts[0]
        port = parts[1]
        # 剩余拼 user:pass —— 但密码一般不含冒号，user 可能含 region 空格
        # 约定：host:port:user:pass 且 pass 是最后一段
        user = ":".join(parts[2:-1])
        pw = parts[-1]
        if port.isdigit():
            return _pack(default_scheme, host, port, user, pw)

    # host:port
    if len(parts) == 2 and parts[1].isdigit():
        return _pack(default_scheme, parts[0], parts[1])
    return None


def resolve_proxy() -> Optional[dict[str, str]]:
    """GROK_PROXY / XAI_PROXY / SAME_SESSION_PROXY 优先。"""
    for key in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY", "HTTPS_PROXY", "HTTP_PROXY"):
        raw = (os.getenv(key) or "").strip()
        if raw:
            parsed = parse_proxy_spec(raw)
            if parsed:
                return parsed
    return None

# 页内二进制 POST（gRPC-web）：body 以 base64 传入，在页面还原 Uint8Array 后 fetch
_PAGE_BINARY_POST_JS = """
async ({url, bodyB64, headers}) => {
  try {
    const bin = atob(bodyB64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      mode: 'cors',
      headers: headers || {},
      body: bytes,
    });
    const ab = await r.arrayBuffer();
    const u8 = new Uint8Array(ab);
    let bodyB64Out = '';
    // 分块 btoa，避免大 body 爆栈
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      bodyB64Out += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    }
    bodyB64Out = btoa(bodyB64Out);
    const hdrs = {};
    try {
      r.headers.forEach((v, k) => { hdrs[k] = v; });
    } catch (e) {}
    return {
      ok: r.ok,
      status: r.status,
      bodyB64: bodyB64Out,
      headers: hdrs,
      error: null,
    };
  } catch (e) {
    return { ok: false, status: 0, bodyB64: '', headers: {}, error: String(e) };
  }
}
"""

# 页内文本 POST（Next.js server action signup）
_PAGE_TEXT_POST_JS = """
async ({url, body, headers}) => {
  try {
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      mode: 'cors',
      headers: headers || {},
      body: body,
    });
    const text = await r.text();
    const hdrs = {};
    try {
      r.headers.forEach((v, k) => { hdrs[k] = v; });
    } catch (e) {}
    return {
      ok: r.ok,
      status: r.status,
      text: text,
      headers: hdrs,
      error: null,
    };
  } catch (e) {
    return { ok: false, status: 0, text: '', headers: {}, error: String(e) };
  }
}
"""

_PAGE_GET_JS = """
async ({url}) => {
  try {
    const r = await fetch(url, { method: 'GET', credentials: 'include', mode: 'cors', redirect: 'follow' });
    return { ok: r.ok, status: r.status, error: null };
  } catch (e) {
    return { ok: false, status: 0, error: String(e) };
  }
}
"""


def _encode_grpc_string(field_id: int, value: str) -> bytes:
    key = (field_id << 3) | 2
    raw = value.encode("utf-8")
    # protobuf varint length（邮箱/验证码都短，单字节即可；长串走 varint）
    length = len(raw)
    length_bytes = b""
    while True:
        b = length & 0x7F
        length >>= 7
        length_bytes += bytes([b | (0x80 if length else 0)])
        if not length:
            break
    return struct.pack("B", key) + length_bytes + raw


def encode_grpc_create_email(email: str) -> bytes:
    payload = _encode_grpc_string(1, email)
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def encode_grpc_verify_email(email: str, code: str) -> bytes:
    payload = _encode_grpc_string(1, email) + _encode_grpc_string(2, code)
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _rand_password(n: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=n)) + "aA1!"


def _rand_name() -> tuple[str, str]:
    first = random.choice(
        ["James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Mia", "Lucas", "Sophia"]
    )
    last = random.choice(
        ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
    )
    return first, last


def _load_action_cache() -> dict[str, str]:
    """
    读 action 缓存；文件不存在/损坏时返回空壳。
    真正可用的 action_id/state_tree 会在打开 sign-up 后由
    _refresh_action_from_page 实时抽取并回写。
    """
    default = {
        "action_id": "",
        "site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
        "state_tree": "",
    }
    path = _BASE / "logs" / "action_id_cache.json"
    try:
        if not path.is_file():
            return default
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default
        return {
            "action_id": (data.get("action_id") or "").strip(),
            "site_key": (data.get("site_key") or default["site_key"]).strip()
            or default["site_key"],
            "state_tree": (data.get("state_tree") or "").strip(),
        }
    except Exception:
        return default


def _save_action_cache(cfg: dict[str, str]) -> None:
    path = _BASE / "logs" / "action_id_cache.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "action_id": cfg.get("action_id"),
                    "site_key": cfg.get("site_key"),
                    "state_tree": cfg.get("state_tree"),
                    "ts": time.time(),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass


def _refresh_action_from_page(page, cfg: dict[str, str], log=None) -> dict[str, str]:
    """
    从当前已打开的 sign-up 页实时抽 action_id / state_tree / site_key。
    缓存过期时 server action 仍 200，但 body 只是 RSC 碎片、没有 set-cookie。
    """
    def _l(m: str) -> None:
        m = _compact_log(m, max_len=120)
        if not m:
            return
        if log:
            try:
                log(m)
                return
            except Exception:
                pass
        print(m, flush=True)

    try:
        html = page.content() or ""
    except Exception:
        html = ""

    # site key
    m = re.search(r'sitekey":"(0x4[a-zA-Z0-9_-]+)"', html)
    if m:
        cfg["site_key"] = m.group(1)

    # state tree（页面 meta / 内联脚本）
    m = re.search(r'next-router-state-tree":"([^"]+)"', html)
    if m:
        cfg["state_tree"] = m.group(1)

    # action id：优先扫当前页已加载的 script src 内容（与 grok.initialize 同规则）
    action = None
    try:
        scripts = page.evaluate(
            """() => Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src)
                .filter(u => u.includes('/_next/static/'))"""
        ) or []
    except Exception:
        scripts = []

    for src in scripts:
        try:
            # 页内 fetch 同源 chunk，避免外部 TLS
            txt = page.evaluate(
                """async (url) => {
                    try {
                      const r = await fetch(url, {credentials:'include'});
                      return await r.text();
                    } catch (e) { return ''; }
                }""",
                src,
            )
            if not txt:
                continue
            m = re.search(r"7f[a-fA-F0-9]{40}", txt)
            if m:
                action = m.group(0)
                break
        except Exception:
            continue

    # 兜底：整页 HTML 里找
    if not action:
        m = re.search(r"7f[a-fA-F0-9]{40}", html)
        if m:
            action = m.group(0)

    if action:
        old = cfg.get("action_id") or ""
        cfg["action_id"] = action
        if action != old:
            _l(f"action 刷新 {action[:12]}…")
            _save_action_cache(cfg)
    # 未命中时静默沿用缓存，不刷屏

    return cfg


def _extract_sso_from_set_cookie_url(url: str) -> Optional[str]:
    """从 auth.*.set-cookie?q=JWT 的 payload 里抠 sso token（兜底）。"""
    try:
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        if not q or q.count(".") < 2:
            return None
        # JWT payload
        pad = "=" * (-len(q.split(".")[1]) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(q.split(".")[1] + pad).decode("utf-8", "ignore")
        )
        # 常见结构: {config:{token:"..."}} 或直接 token 字段
        if isinstance(payload, dict):
            cfg = payload.get("config") or {}
            tok = cfg.get("token") or payload.get("token") or payload.get("sso")
            if isinstance(tok, str) and tok.count(".") >= 2:
                return tok
            # 有时 token 就是整个 cookie value 在别处
            for k in ("sso", "value", "jwt"):
                v = payload.get(k)
                if isinstance(v, str) and v.startswith("eyJ"):
                    return v
        return None
    except Exception:
        return None


def _cookies_sso(cookies: list[dict]) -> tuple[str, str]:
    sso = ""
    sso_rw = ""
    for c in cookies or []:
        name = c.get("name") or ""
        val = c.get("value") or ""
        if name == "sso" and val and not sso:
            sso = val
        if name == "sso-rw" and val and not sso_rw:
            sso_rw = val
    return sso, sso_rw or sso


def _normalize_flight_text(text: str) -> str:
    raw = text or ""
    return (
        raw.replace("\\/", "/")
        .replace("\\u0026", "&")
        .replace("\\u003d", "=")
        .replace("\\u003f", "?")
    )


def _extract_set_cookie_urls(text: str) -> list[str]:
    """
    从 Next.js RSC / flight 响应抠 **完整** 登录 cookie 链接。

    2026-10 起 x.ai 改版：signup 响应不再给 `…/set-cookie?q=…`，
    而是给 **一条** `https://accounts.x.ai/cookie-chain?q=<jwt>`，
    由它 302 串完 auth.x.ai / grok.com / auth.cursor.com 等各跳并下发 cookie。
    只认 set-cookie 会让"注册成功"的响应被判成"无 set-cookie"，
    随后重试又把验证码烧掉 → 表现为注册到最后一步必失败。

    关键：链接在 `18:T9d5,<url>` 这种 text chunk 里，长度常 >2500，
    旧正则/截断会得到残缺 JWT → 跟跳 400/auth-error，永远没 sso。
    必须优先按 flight text chunk 整段取，不要靠短正则。
    """
    raw = _normalize_flight_text(text)
    cleaned: list[str] = []

    def _is_cookie_link(u: str) -> bool:
        return "set-cookie?q=" in u or "cookie-chain?q=" in u

    def _push(u: str, *, exact: bool = False) -> None:
        u = (u or "").strip()
        if not exact:
            u = u.rstrip("\\").rstrip('"').rstrip("'")
            u = re.sub(r"[\r\n].*$", "", u)
            # 去掉 flight 尾巴（如 `1:"$3c"`）；不要再 rstrip("1:")
            # 否则会啃掉 base64url 结尾的合法字符
            u = re.split(r'["\s]', u)[0]
        if not _is_cookie_link(u):
            return
        if not u.startswith("http"):
            return
        if u not in cleaned:
            cleaned.append(u)

    # 1) flight text chunk 精确长度：`18:T9d5,<payload>`（hex 长度）
    for m in re.finditer(r"\d+:T([0-9a-fA-F]+),", raw):
        try:
            ln = int(m.group(1), 16)
        except Exception:
            continue
        if ln <= 0 or ln > 200_000:
            continue
        chunk = raw[m.end() : m.end() + ln]
        if not _is_cookie_link(chunk):
            continue
        # chunk 本身就是完整 URL（长度精确，不能再裁剪）
        if chunk.startswith("http"):
            _push(chunk, exact=True)
        else:
            for u in re.findall(
                r"https://[A-Za-z0-9.-]+/(?:set-cookie|cookie-chain)\?q=[A-Za-z0-9_\-\.]+",
                chunk,
            ):
                _push(u)
    # 2) 兜底：非精确 T 块 / 全文
    if not cleaned:
        for m in re.finditer(
            r"\d+:T[0-9a-fA-F]+,(.+?)(?=\n\d+:|\Z)", raw, re.S
        ):
            chunk = (m.group(1) or "").strip()
            if _is_cookie_link(chunk) and chunk.startswith("http"):
                _push(chunk.split()[0] if chunk.split() else chunk)
    if not cleaned:
        for u in re.findall(
            r"https://[A-Za-z0-9.-]+/(?:set-cookie|cookie-chain)\?q=[A-Za-z0-9_\-\.]+",
            raw,
        ):
            _push(u)

    # 最长优先（完整链入口在最外层，q 最长）
    cleaned.sort(key=len, reverse=True)
    return cleaned


def _cookie_chain_hops(url: str) -> list[str]:
    """
    解析 `…/cookie-chain?q=<jwt>` 里的 hops[]（各站 set-cookie 入口）。

    2026-10 起登录链是「一条 cookie-chain + 多个 hop」：
      auth.x.ai/set-cookie → auth.grokusercontent.com → auth.grok.com → auth.cursor.com
    每个 hop 只对**发起注册的同一浏览器会话**（anon cookie 绑定）下发 cookie，
    独立 curl 会 400。所以必须由同一个 page 依次访问。
    """
    try:
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        if not q or q.count(".") < 2:
            return []
        pad = "=" * ((4 - len(q.split(".")[1]) % 4) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(q.split(".")[1] + pad).decode("utf-8", "ignore")
        )
        hops: list[str] = []
        for h in (payload or {}).get("hops") or []:
            href = str((h or {}).get("href") or "").strip()
            if href.startswith("http") and href not in hops:
                hops.append(href)
        return hops
    except Exception:
        return []


def _expand_set_cookie_chain(url: str, max_depth: int = 8) -> list[str]:
    """解码 q= JWT 里嵌套的 success_url，得到完整跳转链。"""
    chain = [url]
    cur = url
    for _ in range(max_depth):
        try:
            from urllib.parse import parse_qs, urlparse

            q = parse_qs(urlparse(cur).query).get("q", [""])[0]
            if not q or q.count(".") < 2:
                break
            pad = "=" * ((4 - len(q.split(".")[1]) % 4) % 4)
            payload = json.loads(
                base64.urlsafe_b64decode(q.split(".")[1] + pad).decode(
                    "utf-8", "ignore"
                )
            )
            su = ((payload or {}).get("config") or {}).get("success_url")
            if not su or not str(su).startswith("http"):
                break
            su = str(su)
            if su in chain:
                break
            chain.append(su)
            cur = su
        except Exception:
            break
    return chain


def _page_binary_post(page, url: str, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    raw = page.evaluate(
        _PAGE_BINARY_POST_JS,
        {"url": url, "bodyB64": _b64(body), "headers": headers},
    )
    if not isinstance(raw, dict):
        return {"ok": False, "status": 0, "error": f"bad evaluate: {raw!r}", "body": b""}
    body_out = b""
    if raw.get("bodyB64"):
        try:
            body_out = base64.b64decode(raw["bodyB64"])
        except Exception:
            body_out = b""
    return {
        "ok": bool(raw.get("ok")),
        "status": int(raw.get("status") or 0),
        "error": raw.get("error"),
        "headers": raw.get("headers") or {},
        "body": body_out,
    }


def _page_text_post(page, url: str, body: str, headers: dict[str, str]) -> dict[str, Any]:
    raw = page.evaluate(
        _PAGE_TEXT_POST_JS,
        {"url": url, "body": body, "headers": headers},
    )
    if not isinstance(raw, dict):
        return {"ok": False, "status": 0, "error": f"bad evaluate: {raw!r}", "text": ""}
    return {
        "ok": bool(raw.get("ok")),
        "status": int(raw.get("status") or 0),
        "error": raw.get("error"),
        "headers": raw.get("headers") or {},
        "text": str(raw.get("text") or ""),
    }


def _env_bool(name: str, default: Optional[bool] = None) -> Optional[bool]:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _parse_timing_profile(raw: Optional[str] = None) -> dict[str, Any]:
    """
    时序档位（影响 castle 采样窗口 / 行为节奏）:
      fast | normal | slow | human | random
    默认 fast（压空等）；GROK_SAME_SESSION_TIMING 可覆盖。
    """
    name = (raw or os.getenv("GROK_SAME_SESSION_TIMING") or "fast").strip().lower()
    if name in ("rand", "random", "rotate"):
        name = random.choice(["fast", "normal", "slow", "human"])
    presets = {
        # 压秒但仍等 CastleProvider：仅 hasReact 就 mint 会 len=0
        "turbo": {
            "pre_mint_ms": (80, 220),
            "post_react_ms": (60, 180),
            "between_mint_ms": (200, 450),
            "pre_code_ms": (0, 20),
            "pre_verify_ms": (0, 20),
            "pre_turnstile_ms": (0, 20),
            "pre_signup_ms": (0, 40),
            "mint_attempts": 5,
            "networkidle_ms": 1500,
            "react_poll_ms": 150,
            "react_max_waits": 40,  # ~6s，慢代理/慢水合仍等 fiber
            "react_fallback_ms": 1200,
            "require_fiber_token": True,
        },
        # 量产默认：等 createRequestToken 再 mint；Turnstile 并行
        "fast": {
            "pre_mint_ms": (120, 350),
            "post_react_ms": (80, 250),
            "between_mint_ms": (250, 550),
            "pre_code_ms": (0, 40),
            "pre_verify_ms": (0, 30),
            "pre_turnstile_ms": (0, 40),  # 仅同步补解时用；并行成功则跳过
            "pre_signup_ms": (0, 80),
            "mint_attempts": 6,
            "networkidle_ms": 2000,
            "react_poll_ms": 160,
            "react_max_waits": 45,  # ~7s
            "react_fallback_ms": 1500,
            "require_fiber_token": True,
        },
        "normal": {
            "pre_mint_ms": (800, 1800),
            "post_react_ms": (1800, 3200),
            "between_mint_ms": (900, 1600),
            "pre_code_ms": (400, 1000),
            "pre_verify_ms": (400, 1000),
            "pre_turnstile_ms": (600, 1400),
            "pre_signup_ms": (900, 2000),
            "mint_attempts": 7,
            "networkidle_ms": 12000,
            "react_poll_ms": 700,
            "react_max_waits": 25,
            "react_fallback_ms": 3000,
            "require_fiber_token": True,
        },
        "slow": {
            "pre_mint_ms": (1800, 3200),
            "post_react_ms": (3000, 5500),
            "between_mint_ms": (1500, 2800),
            "pre_code_ms": (800, 1600),
            "pre_verify_ms": (800, 1600),
            "pre_turnstile_ms": (1200, 2400),
            "pre_signup_ms": (1800, 3500),
            "mint_attempts": 8,
            "networkidle_ms": 20000,
            "react_poll_ms": 1000,
            "react_max_waits": 30,
            "react_fallback_ms": 5000,
            "require_fiber_token": True,
        },
        "human": {
            "pre_mint_ms": (1200, 2800),
            "post_react_ms": (2500, 5000),
            "between_mint_ms": (1200, 2500),
            "pre_code_ms": (700, 1800),
            "pre_verify_ms": (700, 1800),
            "pre_turnstile_ms": (1000, 2600),
            "pre_signup_ms": (1500, 4000),
            "mint_attempts": 8,
            "networkidle_ms": 15000,
            "react_poll_ms": 800,
            "react_max_waits": 28,
            "react_fallback_ms": 4000,
            "require_fiber_token": True,
        },
    }
    base = presets.get(name, presets["fast"])
    # env 可单独压 networkidle（毫秒）；0 = 跳过
    ni_env = (os.getenv("GROK_SAME_SESSION_NETWORKIDLE_MS") or "").strip()
    if ni_env.isdigit():
        base = {**base, "networkidle_ms": max(0, int(ni_env))}
    return {
        "name": name if name in presets else "fast",
        **base,
    }


def _ts_parallel_enabled() -> bool:
    """Turnstile 与发码/收码并行；GROK_SAME_SESSION_TS_PARALLEL=0 可关。"""
    raw = (os.getenv("GROK_SAME_SESSION_TS_PARALLEL") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no")


# 常见物理屏（宽x高），按 OS 加权；viewport 会略小于 screen（扣任务栏/Dock）
_SCREEN_PRESETS_WIN: list[tuple[int, int, float]] = [
    (1366, 768, 18),
    (1440, 900, 10),
    (1536, 864, 12),
    (1600, 900, 10),
    (1680, 1050, 8),
    (1920, 1080, 28),
    (1920, 1200, 8),
    (2560, 1440, 6),
]
_SCREEN_PRESETS_MAC: list[tuple[int, int, float]] = [
    (1280, 800, 6),
    (1440, 900, 12),
    (1470, 956, 14),  # MBA/MBP scaled
    (1512, 982, 14),
    (1680, 1050, 8),
    (1728, 1117, 12),
    (1920, 1080, 10),
    (2560, 1600, 8),
    (3008, 1692, 4),
]

# WebGL 白名单（避开 SwiftShader / Basic Render / 古董卡，减虚拟机感）
_WEBGL_WIN: list[tuple[str, str, float]] = [
    (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar",
        22,
    ),
    (
        "Google Inc. (NVIDIA)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 480 Direct3D11 vs_5_0 ps_5_0), or similar",
        8,
    ),
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) HD Graphics Direct3D11 vs_5_0 ps_5_0), or similar",
        20,
    ),
    (
        "Google Inc. (Intel)",
        "ANGLE (Intel, Intel(R) HD Graphics 400 Direct3D11 vs_5_0 ps_5_0), or similar",
        16,
    ),
    (
        "Google Inc. (AMD)",
        "ANGLE (AMD, Radeon R9 200 Series Direct3D11 vs_5_0 ps_5_0), or similar",
        12,
    ),
    (
        "Google Inc. (AMD)",
        "ANGLE (AMD, Radeon HD 3200 Graphics Direct3D11 vs_5_0 ps_5_0), or similar",
        6,
    ),
]
# macOS WebGL 必须落在 Camoufox webgl_data.db 的 (vendor,renderer) 上，
# 否则启动直接炸：No WebGL data found for vendor "Apple" and renderer "Apple M2…"
# 本机 db 实测 mac 仅：M1 / Intel HD 400 / Intel HD / Radeon R9 / 极低权 ANGLE-NVIDIA
# 禁止自造 M2/M3/M1 Pro/Iris——库里没有。
_WEBGL_MAC: list[tuple[str, str, float]] = [
    # 几乎纯 M1（Camoufox db 主条目）；少量库内 Intel/AMD 老 Mac 兜底
    ("Apple", "Apple M1, or similar", 94),
    ("Intel Inc.", "Intel(R) HD Graphics 400, or similar", 3),
    ("ATI Technologies Inc.", "Radeon R9 200 Series, or similar", 2),
    ("Intel Inc.", "Intel(R) HD Graphics, or similar", 1),
    # 不抽 mac 上的 ANGLE-NVIDIA（画像拧，虽库内有极低权重）
]

# 真机常见 CPU 线程
_HW_CONCURRENCY_WIN = [(4, 15), (6, 12), (8, 35), (12, 25), (16, 10), (20, 3)]
_HW_CONCURRENCY_MAC = [(8, 40), (10, 25), (12, 20), (16, 12), (24, 3)]


def _weighted_choice(items: list[tuple[Any, float]]) -> Any:
    if not items:
        raise ValueError("empty weighted choice")
    weights = [max(0.0, float(w)) for _, w in items]
    total = sum(weights) or 1.0
    r = random.random() * total
    acc = 0.0
    for val, w in items:
        acc += max(0.0, float(w))
        if r <= acc:
            return val
    return items[-1][0]


def _rand_viewport() -> dict[str, int]:
    """兼容旧调用：随机一个桌面 viewport（不绑 screen 时用）。"""
    profile = build_device_fingerprint("windows")
    return dict(profile["viewport"])


def build_device_fingerprint(
    fp_os: str = "windows",
    *,
    viewport: Optional[dict[str, int]] = None,
) -> dict[str, Any]:
    """
    一号一套「设备上下文」：屏幕、窗口、DPR、WebGL 显卡、CPU 线程、
    媒体设备、Canvas/Audio seed、触控点等，喂给 Camoufox config。

    说明：
      - 浏览器 JS **读不到网卡 MAC**，硬编 MAC 只会露馅，故不伪造。
      - WebRTC 仍 block，避免本机 IP/内网地址泄漏。
      - deviceMemory 非 Camoufox 原生字段，靠 init script 补齐。
    """
    os_l = (fp_os or "windows").strip().lower()
    is_mac = os_l in ("mac", "macos", "osx", "darwin")
    screens = _SCREEN_PRESETS_MAC if is_mac else _SCREEN_PRESETS_WIN
    sw, sh = _weighted_choice([( (w, h), wt) for w, h, wt in screens])
    # 任务栏 / Dock 占用
    chrome_h = random.randint(40, 88) if not is_mac else random.randint(28, 72)
    chrome_w = random.randint(0, 16)
    if viewport and viewport.get("width") and viewport.get("height"):
        vw = max(1100, int(viewport["width"]))
        vh = max(700, int(viewport["height"]))
        # 若外部 viewport 大于 screen，抬高 screen
        sw = max(sw, vw + chrome_w)
        sh = max(sh, vh + chrome_h)
    else:
        vw = max(1100, sw - chrome_w - random.randint(0, 48))
        vh = max(700, sh - chrome_h - random.randint(0, 24))
        # 轻微抖动，避免整批同一窗口
        vw += random.randint(-12, 12)
        vh += random.randint(-10, 10)
        vw = max(1100, min(vw, sw - 8))
        vh = max(700, min(vh, sh - 24))

    dpr_pool = (
        [(2.0, 55), (1.0, 10), (1.5, 5), (2.0, 30)]
        if is_mac
        else [(1.0, 55), (1.25, 20), (1.5, 15), (2.0, 10)]
    )
    dpr = float(_weighted_choice(dpr_pool))
    cores = int(
        _weighted_choice(_HW_CONCURRENCY_MAC if is_mac else _HW_CONCURRENCY_WIN)
    )
    # 设备内存 GB（Navigator.deviceMemory 常见枚举）
    mem = int(
        _weighted_choice(
            [(4, 15), (8, 50), (16, 30), (32, 5)] if not is_mac else [(8, 40), (16, 45), (32, 15)]
        )
    )
    webgl_pool = _WEBGL_MAC if is_mac else _WEBGL_WIN
    vendor, renderer = _weighted_choice(
        [((v, r), wt) for v, r, wt in webgl_pool]
    )
    # OS↔GPU：必须是 Camoufox 库内 pair；未知串一律回退（防 No WebGL data found）
    if is_mac:
        allowed = {(v, r) for v, r, _ in _WEBGL_MAC}
        if (vendor, renderer) not in allowed:
            vendor, renderer = "Apple", "Apple M1, or similar"
    else:
        allowed = {(v, r) for v, r, _ in _WEBGL_WIN}
        r_low = str(renderer or "").lower()
        if (vendor, renderer) not in allowed or (
            "apple m" in r_low and "angle" not in r_low
        ):
            vendor, renderer = _WEBGL_WIN[0][0], _WEBGL_WIN[0][1]
    color_depth = 24
    max_touch = 0  # 桌面
    micros = 1 if random.random() < 0.92 else 0
    speakers = 2 if random.random() < 0.85 else 1
    webcams = 1 if random.random() < (0.55 if is_mac else 0.35) else 0
    sample_rate = 48000 if random.random() < 0.65 else 44100
    max_ch = int(_weighted_choice([(2, 70), (6, 15), (8, 15)]))
    canvas_seed = random.randint(1, 2_147_483_647)
    audio_seed = random.randint(1, 2_147_483_647)
    hist_len = random.randint(1, 5)

    return {
        "fp_os": "macos" if is_mac else "windows",
        "screen": {"width": int(sw), "height": int(sh)},
        "viewport": {"width": int(vw), "height": int(vh)},
        "window": {"width": int(vw), "height": int(vh)},
        "device_pixel_ratio": dpr,
        "color_depth": color_depth,
        "hardware_concurrency": cores,
        "device_memory_gb": mem,
        "max_touch_points": max_touch,
        "webgl_vendor": vendor,
        "webgl_renderer": renderer,
        "media_micros": micros,
        "media_speakers": speakers,
        "media_webcams": webcams,
        "audio_sample_rate": sample_rate,
        "audio_max_channels": max_ch,
        "canvas_seed": canvas_seed,
        "audio_seed": audio_seed,
        "history_length": hist_len,
    }


def device_fp_camoufox_kwargs(device_fp: dict[str, Any]) -> dict[str, Any]:
    """
    把 build_device_fingerprint 结果映射成 Camoufox(**kwargs) 片段。

    注意：不要用过紧的 browserforge Screen 约束——会和 window/os 组合
    撞成「No headers can be generated」。屏幕尺寸一律走 config 覆盖。
    """
    if not device_fp:
        return {}
    sw = int((device_fp.get("screen") or {}).get("width") or 1920)
    sh = int((device_fp.get("screen") or {}).get("height") or 1080)
    win = device_fp.get("window") or device_fp.get("viewport") or {}
    ww = int(win.get("width") or 1440)
    wh = int(win.get("height") or 900)
    # window 不得大于 screen（BrowserForge 常识）
    ww = max(1100, min(ww, sw))
    wh = max(700, min(wh, sh - 20))
    vendor = str(device_fp.get("webgl_vendor") or "").strip()
    renderer = str(device_fp.get("webgl_renderer") or "").strip()
    out: dict[str, Any] = {
        "window": (ww, wh),
        "block_webgl": False,
    }
    # 宽松 screen 上限，仅作生成器天花板；真实值由 config 钉死
    try:
        from browserforge.fingerprints import Screen

        out["screen"] = Screen(
            min_width=1024,
            max_width=max(sw, 3840),
            min_height=700,
            max_height=max(sh, 2160),
        )
    except Exception:
        pass
    if vendor and renderer:
        out["webgl_config"] = (vendor, renderer)

    avail_h = max(600, sh - random.randint(0, 48))
    cfg: dict[str, Any] = {
        "navigator.hardwareConcurrency": int(
            device_fp.get("hardware_concurrency") or 8
        ),
        "navigator.maxTouchPoints": int(device_fp.get("max_touch_points") or 0),
        "window.devicePixelRatio": float(device_fp.get("device_pixel_ratio") or 1.0),
        "screen.colorDepth": int(device_fp.get("color_depth") or 24),
        "screen.pixelDepth": int(device_fp.get("color_depth") or 24),
        "screen.width": sw,
        "screen.height": sh,
        "screen.availWidth": sw,
        "screen.availHeight": avail_h,
        "screen.availLeft": 0,
        "screen.availTop": 0,
        "window.outerWidth": ww,
        "window.outerHeight": wh,
        "window.innerWidth": max(800, ww - random.randint(0, 2)),
        "window.innerHeight": max(600, wh - random.randint(0, 8)),
        "window.history.length": int(device_fp.get("history_length") or 2),
        "mediaDevices:enabled": True,
        "mediaDevices:micros": int(device_fp.get("media_micros") or 1),
        "mediaDevices:speakers": int(device_fp.get("media_speakers") or 2),
        "mediaDevices:webcams": int(device_fp.get("media_webcams") or 0),
        "canvas:seed": int(device_fp.get("canvas_seed") or random.randint(1, 10**9)),
        "canvas:aaOffset": random.randint(-50, 50),
        "canvas:aaCapOffset": True,
        "audio:seed": int(device_fp.get("audio_seed") or random.randint(1, 10**9)),
        "AudioContext:sampleRate": int(device_fp.get("audio_sample_rate") or 48000),
        "AudioContext:maxChannelCount": int(device_fp.get("audio_max_channels") or 2),
        "AudioContext:outputLatency": round(random.uniform(0.01, 0.05), 4),
    }
    out["config"] = cfg
    # 手动 config 会触发 LeakWarning；声明我们清楚在做指纹拼装
    out["i_know_what_im_doing"] = True
    return out


def _apply_device_context(page, device_fp: Optional[dict[str, Any]]) -> None:
    """
    补 Camoufox 不一定覆盖的上下文：deviceMemory、userAgentData 粗糙位、
    以及 screen/viewport 一致性兜底（双保险）。
    """
    if not device_fp or page is None:
        return
    try:
        mem = int(device_fp.get("device_memory_gb") or 8)
        cores = int(device_fp.get("hardware_concurrency") or 8)
        dpr = float(device_fp.get("device_pixel_ratio") or 1.0)
        max_touch = int(device_fp.get("max_touch_points") or 0)
        sw = int((device_fp.get("screen") or {}).get("width") or 0)
        sh = int((device_fp.get("screen") or {}).get("height") or 0)
        platform = (
            "MacIntel"
            if str(device_fp.get("fp_os") or "").lower().startswith("mac")
            else "Win32"
        )
        vendor = json.dumps(str(device_fp.get("webgl_vendor") or ""), ensure_ascii=False)
        renderer = json.dumps(
            str(device_fp.get("webgl_renderer") or ""), ensure_ascii=False
        )
        page.add_init_script(
            f"""(() => {{
              try {{
                const mem = {mem};
                const cores = {cores};
                const dpr = {dpr};
                const maxTouch = {max_touch};
                const sw = {sw};
                const sh = {sh};
                const platform = {json.dumps(platform)};
                const glVendor = {vendor};
                const glRenderer = {renderer};
                try {{
                  Object.defineProperty(Navigator.prototype, 'deviceMemory', {{
                    get: () => mem, configurable: true
                  }});
                }} catch (e) {{}}
                try {{
                  Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{
                    get: () => cores, configurable: true
                  }});
                }} catch (e) {{}}
                try {{
                  Object.defineProperty(Navigator.prototype, 'maxTouchPoints', {{
                    get: () => maxTouch, configurable: true
                  }});
                }} catch (e) {{}}
                try {{
                  Object.defineProperty(Navigator.prototype, 'platform', {{
                    get: () => platform, configurable: true
                  }});
                }} catch (e) {{}}
                try {{
                  Object.defineProperty(window, 'devicePixelRatio', {{
                    get: () => dpr, configurable: true
                  }});
                }} catch (e) {{}}
                if (sw > 0 && sh > 0) {{
                  try {{
                    Object.defineProperty(screen, 'width', {{ get: () => sw, configurable: true }});
                    Object.defineProperty(screen, 'height', {{ get: () => sh, configurable: true }});
                    Object.defineProperty(screen, 'availWidth', {{ get: () => sw, configurable: true }});
                    Object.defineProperty(screen, 'availHeight', {{
                      get: () => Math.max(600, sh - 40), configurable: true
                    }});
                    Object.defineProperty(screen, 'colorDepth', {{ get: () => 24, configurable: true }});
                    Object.defineProperty(screen, 'pixelDepth', {{ get: () => 24, configurable: true }});
                  }} catch (e) {{}}
                }}
                // WebGL UNMASKED_* 双保险（Camoufox 已注入时此段为 no-op 失败也无妨）
                if (glVendor && glRenderer) {{
                  try {{
                    const patch = (proto) => {{
                      if (!proto || !proto.getParameter) return;
                      const raw = proto.getParameter;
                      proto.getParameter = function(p) {{
                        const dbg = this.getExtension && this.getExtension('WEBGL_debug_renderer_info');
                        if (dbg) {{
                          if (p === dbg.UNMASKED_VENDOR_WEBGL) return glVendor;
                          if (p === dbg.UNMASKED_RENDERER_WEBGL) return glRenderer;
                        }}
                        return raw.apply(this, arguments);
                      }};
                    }};
                    if (window.WebGLRenderingContext) patch(WebGLRenderingContext.prototype);
                    if (window.WebGL2RenderingContext) patch(WebGL2RenderingContext.prototype);
                  }} catch (e) {{}}
                }}
              }} catch (e) {{}}
            }})();"""
        )
    except Exception:
        pass


def locale_language_pack(locale: Optional[str] = None) -> dict[str, Any]:
    """
    语言跟随地区 locale：
      - locale: BCP47 主语言（en-US / ja-JP …）
      - lang: 短码（en / ja）→ --lang / document
      - languages: navigator.languages 风格列表
      - accept_language: HTTP Accept-Language（q 值链）
    """
    loc = (locale or "en-US").strip().replace("_", "-") or "en-US"
    # 规范化大小写：en-us → en-US
    parts = loc.split("-")
    if len(parts) >= 2:
        loc = parts[0].lower() + "-" + parts[1].upper()
        if len(parts) > 2:
            loc = loc + "-" + "-".join(parts[2:])
    else:
        loc = parts[0].lower()
    lang = loc.split("-", 1)[0].lower() or "en"

    # 常见地区语言链（主语言 + 英语兜底，贴近真浏览器）
    chains: dict[str, list[str]] = {
        "en-US": ["en-US", "en"],
        "en-GB": ["en-GB", "en"],
        "en-AU": ["en-AU", "en-GB", "en"],
        "en-CA": ["en-CA", "en-US", "en"],
        "en-IE": ["en-IE", "en-GB", "en"],
        "en-NZ": ["en-NZ", "en-GB", "en"],
        "en-SG": ["en-SG", "en-GB", "en"],
        "en-MY": ["en-MY", "en-GB", "en"],
        "en-IN": ["en-IN", "en-GB", "en"],
        "ja-JP": ["ja-JP", "ja", "en-US", "en"],
        "ko-KR": ["ko-KR", "ko", "en-US", "en"],
        "zh-TW": ["zh-TW", "zh-Hant", "zh", "en-US", "en"],
        "zh-HK": ["zh-HK", "zh-Hant", "zh", "en-US", "en"],
        "zh-CN": ["zh-CN", "zh", "en-US", "en"],
        "de-DE": ["de-DE", "de", "en-US", "en"],
        "de-CH": ["de-CH", "de", "en-US", "en"],
        "fr-FR": ["fr-FR", "fr", "en-US", "en"],
        "nl-NL": ["nl-NL", "nl", "en-US", "en"],
        "es-ES": ["es-ES", "es", "en-US", "en"],
        "es-MX": ["es-MX", "es-ES", "es", "en-US", "en"],
        "it-IT": ["it-IT", "it", "en-US", "en"],
        "sv-SE": ["sv-SE", "sv", "en-US", "en"],
        "pl-PL": ["pl-PL", "pl", "en-US", "en"],
        "pt-BR": ["pt-BR", "pt", "en-US", "en"],
        "pt-PT": ["pt-PT", "pt", "en-US", "en"],
    }
    languages = list(chains.get(loc) or [])
    if not languages:
        # 未知 locale：主 tag + 语言短码 + en
        languages = [loc]
        if lang and lang != loc.lower():
            languages.append(lang)
        if lang != "en":
            languages.extend(["en-US", "en"])
        else:
            if "en" not in languages:
                languages.append("en")

    # Accept-Language：q 递减
    al_parts: list[str] = []
    for i, item in enumerate(languages):
        if i == 0:
            al_parts.append(item)
        else:
            q = max(0.3, round(1.0 - 0.1 * i, 1))
            # 常见：第二项 0.9，其后 0.8…
            if i == 1:
                q = 0.9
            elif i == 2:
                q = 0.8
            elif i == 3:
                q = 0.7
            else:
                q = max(0.5, round(0.9 - 0.1 * (i - 1), 1))
            al_parts.append(f"{item};q={q}")
    accept_language = ",".join(al_parts)
    return {
        "locale": loc,
        "lang": lang,
        "languages": languages,
        "accept_language": accept_language,
    }


def _context_locale_kwargs(
    locale: str,
    timezone_id: str,
    vp: dict[str, int],
    *,
    accept_language: Optional[str] = None,
) -> dict[str, Any]:
    """Playwright/Camoufox new_context 公共参数：locale + 时区 + Accept-Language。"""
    pack = locale_language_pack(locale)
    al = (accept_language or pack["accept_language"]).strip()
    kw: dict[str, Any] = {
        "viewport": {"width": int(vp["width"]), "height": int(vp["height"])},
        "locale": pack["locale"],
        "timezone_id": timezone_id,
        "extra_http_headers": {
            "Accept-Language": al,
        },
    }
    return kw


def _apply_navigator_languages(page, languages: list[str], lang: str) -> None:
    """补 navigator.language / languages，与 locale 一致（防只改 HTTP 头）。"""
    try:
        langs = [str(x) for x in (languages or []) if x]
        if not langs:
            return
        primary = (lang or langs[0].split("-")[0] or "en").strip()
        # add_init_script 不收额外参数，语言表直接嵌进脚本
        langs_js = json.dumps(langs, ensure_ascii=False)
        primary_js = json.dumps(primary, ensure_ascii=False)
        page.add_init_script(
            f"""(() => {{
              try {{
                const langs = {langs_js};
                const primary = {primary_js} || (langs[0] || 'en-US');
                Object.defineProperty(Navigator.prototype, 'language', {{
                  get: () => primary,
                  configurable: true,
                }});
                Object.defineProperty(Navigator.prototype, 'languages', {{
                  get: () => Object.freeze(langs.slice()),
                  configurable: true,
                }});
              }} catch (e) {{}}
            }})();"""
        )
    except Exception:
        pass


def same_session_register(
    *,
    email: str,
    password: Optional[str] = None,
    given_name: Optional[str] = None,
    family_name: Optional[str] = None,
    verification_code: Optional[str] = None,
    fetch_code: Optional[Any] = None,
    turnstile_token: Optional[str] = None,
    solve_turnstile: Optional[Any] = None,
    headless: Optional[bool] = None,
    timeout_s: int = 120,
    profile_dir: Optional[Path] = None,
    fresh_profile: bool = True,
    proxy: Optional[str] = None,
    log: Optional[Any] = None,
    # 可选覆盖（矩阵测试 / 一号一换）。不传则读环境变量。
    browser: Optional[str] = None,
    fp_os: Optional[str] = None,
    locale: Optional[str] = None,
    timezone_id: Optional[str] = None,
    humanize: Optional[bool] = None,
    timing: Optional[str] = None,
    viewport: Optional[dict[str, int]] = None,
    device_fp: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    同会话协议注册（页内 fetch，不走 page.request）。

    默认 camoufox 真无头（页面跑不弹窗；已验证 CLEAN）。
    GROK_SAME_SESSION_HEADLESS=offscreen → 有头 Chrome 挪屏外（可能闪窗）。
    GROK_SAME_SESSION_HEADLESS=1/headless → Chrome --headless=new。
    GROK_SAME_SESSION_HEADLESS=0/gui → 可见 Chrome 窗口。
    默认直连、不用代理。proxy 仅在显式传入时启用（可选）。

    一号一换旋钮（env 或参数）:
      browser/fp_os/locale/timezone/humanize/timing/viewport/device_fp
      device_fp: WebGL/屏幕/DPR/CPU/媒体/canvas 等（见 build_device_fingerprint）
    """
    def _log(msg: str) -> None:
        """只打一行：有外部 log 回调就只走回调，绝不双份 print。"""
        msg = _compact_log(msg, max_len=160)
        if not msg:
            return
        if log:
            try:
                log(msg)
                return
            except Exception:
                pass
        print(msg, flush=True)

    def _sleep_ms(lo_hi: tuple[int, int], tag: str = "") -> int:
        lo, hi = int(lo_hi[0]), int(lo_hi[1])
        if hi < lo:
            lo, hi = hi, lo
        ms = random.randint(lo, hi)
        if ms > 0:
            try:
                # page 未就绪时用 time.sleep
                time.sleep(ms / 1000.0)
            except Exception:
                pass
        if tag:
            out_steps_ref.append(f"wait:{tag}:{ms}ms")
        return ms

    # 显示/引擎：
    # - 默认 / camoufox：Camoufox 真无头（页面不弹窗，已验证 CLEAN）
    # - offscreen：Chrome 有头 + 屏外（可能闪窗/多屏仍可见）
    # - 1/true/headless：Chrome --headless=new
    # - 0/gui/headed：Chrome 可见窗口
    display_mode = "camoufox"
    browser_engine = "camoufox"
    raw_browser = (browser or os.getenv("GROK_SAME_SESSION_BROWSER") or "").strip().lower()
    if headless is True:
        display_mode = "headless"
        browser_engine = "chrome"
    elif headless is False:
        display_mode = "gui"
        browser_engine = "chrome"
    else:
        raw = (
            os.getenv("GROK_SAME_SESSION_HEADLESS") or "camoufox"
        ).strip().lower()
        # 参数 browser 优先
        if raw_browser in ("camoufox", "cf", "fox"):
            raw = "camoufox"
        elif raw_browser in ("chrome", "offscreen"):
            raw = "offscreen"
        elif raw_browser in ("chrome-headless", "headless"):
            raw = "headless"
        elif raw_browser in ("gui", "headed"):
            raw = "gui"
        eng_raw = raw_browser
        if eng_raw in ("camoufox", "cf", "fox") or raw in (
            "camoufox",
            "cf",
            "camoufox-headless",
            "cf-headless",
        ):
            display_mode = "camoufox"
            browser_engine = "camoufox"
        elif raw in ("1", "true", "yes", "headless"):
            display_mode = "headless"
            browser_engine = "chrome"
        elif raw in ("0", "false", "off", "no", "gui", "headed"):
            display_mode = "gui"
            browser_engine = "chrome"
        elif raw in ("offscreen", "chrome-offscreen"):
            display_mode = "offscreen"
            browser_engine = "chrome"
        else:
            # 未知值 → camoufox，别误开有头窗
            display_mode = "camoufox"
            browser_engine = "camoufox"
    use_headless = display_mode in ("headless", "camoufox")

    given = given_name or _rand_name()[0]
    family = family_name or _rand_name()[1]
    password = password or _rand_password()
    conversion_id = new_conversion_id()
    cfg = _load_action_cache()

    # proxy 显式传入优先；否则认 GROK_PROXY / XAI_PROXY（与注册机业务代理对齐）
    if proxy:
        proxy_info = parse_proxy_spec(proxy)
    else:
        proxy_info = resolve_proxy()

    locale_raw = (locale or os.getenv("GROK_LOCALE") or "").strip() or "en-US"
    lang_pack = locale_language_pack(locale_raw)
    locale = lang_pack["locale"]
    accept_language = lang_pack["accept_language"]
    nav_languages = list(lang_pack["languages"])
    lang_short = lang_pack["lang"]
    timezone_id = (timezone_id or os.getenv("GROK_TIMEZONE") or "").strip() or "America/New_York"
    timing_cfg = _parse_timing_profile(timing)
    out_steps_ref: list[str] = []

    # 指纹 OS（Camoufox）：默认 windows；禁止 linux（超哥硬规则）
    fp_os_raw = (fp_os or os.getenv("GROK_SAME_SESSION_OS") or "windows").strip().lower()
    if fp_os_raw in ("rand", "random", "rotate", "any"):
        # 随机池也不含 linux
        fp_os_val = random.choice(["windows", "macos"])
    elif fp_os_raw in ("win", "windows"):
        fp_os_val = "windows"
    elif fp_os_raw in ("mac", "macos", "osx", "darwin"):
        fp_os_val = "macos"
    elif fp_os_raw in ("lin", "linux"):
        # 禁止 linux 指纹：强制回落 windows，避免 silent 污染
        try:
            _log("fp_os=linux 不支持，已改 windows")
        except Exception:
            pass
        fp_os_val = "windows"
    else:
        fp_os_val = "windows"

    humanize_val = humanize if humanize is not None else _env_bool("GROK_SAME_SESSION_HUMANIZE", True)
    if humanize_val is None:
        humanize_val = True
    # 设备指纹：外部可传完整 profile；缺字段时用 build_device_fingerprint 补齐
    if device_fp and isinstance(device_fp, dict) and device_fp.get("webgl_renderer"):
        dev_fp = dict(device_fp)
        if viewport and viewport.get("width"):
            dev_fp["viewport"] = dict(viewport)
            if not dev_fp.get("window"):
                dev_fp["window"] = dict(viewport)
    else:
        dev_fp = build_device_fingerprint(fp_os_val, viewport=viewport)
        if device_fp and isinstance(device_fp, dict):
            for k, v in device_fp.items():
                if v is not None:
                    dev_fp[k] = v
    vp = dict(dev_fp.get("viewport") or viewport or _rand_viewport())
    dev_fp["viewport"] = vp
    if not dev_fp.get("window"):
        dev_fp["window"] = dict(vp)
    dev_fp["fp_os"] = (
        "macos"
        if str(fp_os_val).lower() in ("mac", "macos", "osx", "darwin")
        else "windows"
    )

    out: dict[str, Any] = {
        "ok": False,
        "email": email,
        "password": password,
        "given": given,
        "family": family,
        "conversion_id": conversion_id,
        "castle_len": 0,
        "castle_method": None,
        "signup_status": None,
        "sso": None,
        "sso_rw": None,
        "error": None,
        "steps": out_steps_ref,
        "elapsed_s": 0.0,
        "mode": "same_session_page_fetch",
        "browser_engine": browser_engine,
        "display_mode": display_mode,
        "proxy_server": None,
        "locale": locale,
        "lang": lang_short,
        "languages": nav_languages,
        "accept_language": accept_language,
        "timezone": timezone_id,
        "fp_os": fp_os_val,
        "humanize": bool(humanize_val),
        "timing": timing_cfg["name"],
        "viewport": vp,
        "device_fp": {
            k: dev_fp.get(k)
            for k in (
                "screen",
                "device_pixel_ratio",
                "hardware_concurrency",
                "device_memory_gb",
                "webgl_vendor",
                "webgl_renderer",
                "media_micros",
                "media_speakers",
                "media_webcams",
                "color_depth",
                "max_touch_points",
            )
        },
    }
    t0 = time.time()

    if profile_dir is None:
        profile_dir = DEFAULT_PROFILE_ROOT / uuid.uuid4().hex[:10]
    profile_dir = Path(profile_dir)
    if fresh_profile and profile_dir.exists():
        shutil.rmtree(profile_dir, ignore_errors=True)
    profile_dir.mkdir(parents=True, exist_ok=True)
    out["profile"] = str(profile_dir)

    # 只清系统杂代理，保留 GROK_PROXY/XAI_PROXY（多账号时下一号还要用）
    _saved_biz = {
        k: os.environ.get(k)
        for k in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY")
        if os.environ.get(k)
    }
    for k in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        os.environ.pop(k, None)
    # Playwright 走 launch_kwargs.proxy，进程级业务代理先摘掉避免双重代理
    for k in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY"):
        os.environ.pop(k, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"
    out["steps"].append("env:clear_sys_proxy")

    if proxy_info and proxy_info.get("server"):
        out["proxy_server"] = proxy_info.get("server")
        out["steps"].append(f"proxy:{proxy_info.get('server')}")
        _log(f"代理 {proxy_info.get('server')}")
    else:
        out["steps"].append("proxy:off")
        _log("代理 直连")

    pw_proxy: Optional[dict[str, str]] = None
    if proxy_info and proxy_info.get("server"):
        pw_proxy = {"server": proxy_info["server"]}
        if proxy_info.get("username"):
            pw_proxy["username"] = proxy_info["username"]
            pw_proxy["password"] = proxy_info.get("password") or ""

    # Firefox/Camoufox 不支持 SOCKS5 用户名密码 → 本机 HTTP 桥接上游 SOCKS5
    # curl 探测能通、浏览器 goto 超时，就是这个坑。
    if pw_proxy and proxy_info:
        server_l = str(proxy_info.get("server") or pw_proxy.get("server") or "").lower()
        need_bridge = server_l.startswith("socks5") and bool(
            pw_proxy.get("username") or proxy_info.get("username")
        )
        if need_bridge:
            try:
                from g.socks5_http_bridge import ensure_socks5_http_bridge

                bridge_src = (
                    proxy_info.get("server_url")
                    or proxy
                    or proxy_info.get("server")
                    or ""
                )
                bridged = ensure_socks5_http_bridge(str(bridge_src))
                if bridged and bridged.get("server"):
                    _log(
                        f"SOCKS5鉴权→本机桥 {bridged['server']} "
                        f"(Firefox 不支持 socks5 auth)"
                    )
                    out["steps"].append(f"proxy_bridge:{bridged['server']}")
                    out["proxy_bridge"] = bridged["server"]
                    pw_proxy = {"server": bridged["server"]}
            except Exception as be:
                out["error"] = f"SOCKS5 本机桥失败: {be}"
                return out

    castle = ""
    ctx = None
    camoufox_cm = None
    camoufox_browser = None
    from_pool = False
    try:
        # ---------- 启动浏览器：Camoufox 真无头 or Chrome ----------
        if browser_engine == "camoufox":
            try:
                from camoufox.sync_api import Camoufox  # noqa: F401
            except Exception as e:
                out["error"] = f"camoufox 不可用: {e}"
                return out
            try:
                camoufox_cm, ctx, page, from_pool, launch_s = _acquire_camoufox_pooled(
                    fp_os_val=fp_os_val,
                    locale=locale,
                    humanize_val=bool(humanize_val),
                    vp=vp,
                    pw_proxy=pw_proxy,
                    timezone_id=timezone_id,
                    log_fn=_log,
                    accept_language=accept_language,
                    languages=nav_languages,
                    device_fp=dev_fp,
                )
            except Exception as e:
                out["error"] = f"camoufox 启动失败: {e}"
                return out
            out["browser_from_pool"] = bool(from_pool)
            out["browser_launch_s"] = launch_s
            out["viewport"] = vp
            out["steps"].append(
                f"engine:camoufox-headless:os={fp_os_val}:hum={int(bool(humanize_val))}"
                f":lang={locale}:pool={int(bool(from_pool))}:launch={launch_s}s"
            )
            out["steps"].append(f"accept_language:{accept_language[:48]}")
            _gpu = str(dev_fp.get("webgl_renderer") or "")[:40]
            out["steps"].append(
                f"device:screen={((dev_fp.get('screen') or {}).get('width'))}x"
                f"{((dev_fp.get('screen') or {}).get('height'))}"
                f":dpr={dev_fp.get('device_pixel_ratio')}"
                f":hw={dev_fp.get('hardware_concurrency')}"
                f":mem={dev_fp.get('device_memory_gb')}"
                f":gpu={_gpu}"
            )
        else:
            try:
                from playwright.sync_api import sync_playwright
            except Exception as e:
                out["error"] = f"playwright 不可用: {e}"
                return out
            _log(
                f"启动 chrome · {display_mode} · {locale} · al={accept_language[:36]}"
            )
            p = sync_playwright().start()
            out["_pw"] = p
            chrome_args = [
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-dev-shm-usage",
                f"--window-size={int(vp['width'])},{int(vp['height'])}",
                # --lang 用短码更稳（ja / de / en-US 均可；优先 BCP47）
                f"--lang={locale}",
                f"--accept-lang={accept_language}",
            ]
            if display_mode == "headless":
                chrome_args.append("--headless=new")
            elif display_mode == "offscreen":
                # 有头 Chrome 挪到屏外：过 CF 接近真有头。
                # 不要 --start-minimized：最小化会节流 rAF/定时器，Castle 起不来。
                chrome_args.extend(
                    [
                        "--window-position=-2400,-2400",
                    ]
                )

            ctx_kw = _context_locale_kwargs(
                locale, timezone_id, vp, accept_language=accept_language
            )
            launch_kwargs: dict[str, Any] = {
                "user_data_dir": str(profile_dir),
                "channel": "chrome",
                "headless": use_headless and display_mode == "headless",
                "args": chrome_args,
                **ctx_kw,
            }
            if pw_proxy:
                launch_kwargs["proxy"] = pw_proxy
            t_launch = time.time()
            ctx = p.chromium.launch_persistent_context(**launch_kwargs)
            _log(f"chrome 就绪 · {time.time()-t_launch:.1f}s")
            out["steps"].append(f"engine:chrome-{display_mode}")
            out["steps"].append(f"accept_language:{accept_language[:48]}")

        try:
            if browser_engine != "camoufox":
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                _apply_navigator_languages(page, nav_languages, lang_short)
            page.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            )
            if display_mode == "offscreen" and browser_engine == "chrome":
                try:
                    # 再保险：把所有页窗口推到屏外
                    for pg in ctx.pages:
                        try:
                            pg.evaluate(
                                "() => { try { window.moveTo(-2400,-2400); "
                                "window.resizeTo(1365,900); } catch(e){} }"
                            )
                        except Exception:
                            pass
                except Exception:
                    pass

            nav_timeout = min(90000, max(30000, int(timeout_s) * 1000))
            t_goto = time.time()
            # 代理出口偶发慢/超时：重试一次，避免整个邮箱因为一次 goto 超时被废掉
            try:
                page.goto(
                    f"{SITE}/sign-up",
                    wait_until="domcontentloaded",
                    timeout=nav_timeout,
                )
            except Exception as goto_err:
                _log(f"sign-up 首跳失败，重试一次 · {_compact_log(goto_err, 80)}")
                out["steps"].append(f"goto_retry:{type(goto_err).__name__}")
                try:
                    page.wait_for_timeout(1200)
                except Exception:
                    time.sleep(1.2)
                page.goto(
                    f"{SITE}/sign-up",
                    wait_until="domcontentloaded",
                    timeout=nav_timeout,
                )
            _log(f"sign-up 就绪 · {time.time()-t_goto:.1f}s")
            # networkidle 太长会空烧；fast 默认 5s，可用 env 覆盖
            ni_ms = int(timing_cfg.get("networkidle_ms") or 5000)
            if ni_ms > 0:
                try:
                    page.wait_for_load_state("networkidle", timeout=ni_ms)
                except Exception:
                    pass

            # 协议路径：不点 UI。必须等 CastleProvider.createRequestToken 上树，
            # 仅 hasReact 就 mint → fiber mint failed len=0（慢代理 sign-up 20s+ 时必现）。
            _FIBER_READY_JS = r"""() => {
              const out = {
                hasReact: false,
                enableCastle: false,
                hasCastle: !!(window.Castle || window._castle || window.__castle),
                castleScripts: 0,
                hasFiberNode: false,
                hasCreateRequestToken: false,
                via: null,
                bodyLen: (document.body && document.body.innerHTML || '').length,
              };
              try {
                out.enableCastle = (document.documentElement.innerHTML||'')
                  .includes('enableCastle');
                out.castleScripts = [...document.scripts]
                  .map(s => s.src || '')
                  .filter(s => /castle/i.test(s)).length;
                if (window.__castleCreate && typeof window.__castleCreate === 'function') {
                  out.hasCreateRequestToken = true;
                  out.via = 'cache';
                }
                const roots = [
                  document.documentElement, document.body,
                  document.getElementById('root'), document.getElementById('__next'),
                ].filter(Boolean);
                const extra = [...document.querySelectorAll('div,main,section')].slice(0, 120);
                function walk(node, depth, bag) {
                  if (!node || depth > 70 || bag.fn) return;
                  try {
                    const props = node.memoizedProps || node.pendingProps || {};
                    const val = props.value || props;
                    if (val && typeof val.createRequestToken === 'function') {
                      bag.fn = val.createRequestToken; bag.via = 'value';
                    } else if (typeof props.createRequestToken === 'function') {
                      bag.fn = props.createRequestToken; bag.via = 'props';
                    }
                  } catch (e) {}
                  if (bag.fn) return;
                  if (node.child) walk(node.child, depth + 1, bag);
                  if (!bag.fn && node.sibling) walk(node.sibling, depth + 1, bag);
                }
                const bag = {fn: null, via: null};
                for (const el of [...roots, ...extra]) {
                  for (const k of Object.keys(el)) {
                    if (k.startsWith('__react') || k.startsWith('__reactFiber')
                        || k.startsWith('__reactContainer')
                        || k.startsWith('__reactInternalInstance')) {
                      out.hasReact = true;
                      out.hasFiberNode = true;
                      if (!bag.fn) walk(el[k], 0, bag);
                    }
                  }
                  if (bag.fn) break;
                }
                if (bag.fn) {
                  try { window.__castleCreate = bag.fn; } catch (e) {}
                  out.hasCreateRequestToken = true;
                  out.via = bag.via;
                }
              } catch (e) {
                out.err = String(e && e.message || e);
              }
              return out;
            }"""
            react_ok = False
            fiber_token_ok = False
            react_poll = int(timing_cfg.get("react_poll_ms") or 350)
            react_max = int(timing_cfg.get("react_max_waits") or 18)
            require_fiber = bool(timing_cfg.get("require_fiber_token", True))
            # 慢导航（sign-up 20s+）再多给一轮预算
            try:
                nav_s = float(out.get("steps") and 0)
            except Exception:
                nav_s = 0
            t_react = time.time()
            last_st: dict[str, Any] = {}
            for w in range(1, react_max + 1):
                try:
                    st = page.evaluate(_FIBER_READY_JS)
                except Exception as e:
                    st = {"err": str(e)}
                if isinstance(st, dict):
                    last_st = st
                    ready_core = bool(st.get("hasReact") or st.get("hasFiberNode"))
                    fiber_token_ok = bool(st.get("hasCreateRequestToken"))
                    ready_castle_hint = bool(
                        st.get("enableCastle")
                        or st.get("hasCastle")
                        or int(st.get("castleScripts") or 0) > 0
                    )
                    # 硬门槛：有 createRequestToken 才算真就绪（默认真）
                    if fiber_token_ok:
                        react_ok = True
                        _log(
                            f"React/Castle 就绪 · fiber=ok via={st.get('via')} · "
                            f"{time.time()-t_react:.1f}s"
                        )
                        break
                    # 兼容：明确关闭 require 时，React+线索也可进（不推荐）
                    if (
                        not require_fiber
                        and ready_core
                        and ready_castle_hint
                    ):
                        react_ok = True
                        _log(
                            f"React/Castle 就绪(宽松) · {time.time()-t_react:.1f}s"
                        )
                        break
                page.wait_for_timeout(react_poll)
            if not react_ok:
                try:
                    title = page.title()
                    body_len = len(page.content() or "")
                except Exception:
                    title, body_len = "?", 0
                _log(
                    f"CastleProvider 未就绪 · title={title!r} len={body_len} "
                    f"fiberToken={last_st.get('hasCreateRequestToken')} "
                    f"react={last_st.get('hasReact')} · 再等/软刷新"
                )
                page.wait_for_timeout(int(timing_cfg.get("react_fallback_ms") or 1200))
                # 软刷新一次：慢代理下 Castle chunk 常晚到，刷新后 fiber 更稳
                try:
                    page.reload(wait_until="domcontentloaded", timeout=nav_timeout)
                    out["steps"].append("reload:castle_wait")
                    _log("sign-up 软刷新以挂 CastleProvider…")
                    ni_ms2 = int(timing_cfg.get("networkidle_ms") or 2000)
                    if ni_ms2 > 0:
                        try:
                            page.wait_for_load_state(
                                "networkidle", timeout=min(ni_ms2, 8000)
                            )
                        except Exception:
                            pass
                    for w in range(1, max(12, react_max // 2) + 1):
                        try:
                            st = page.evaluate(_FIBER_READY_JS)
                        except Exception as e:
                            st = {"err": str(e)}
                        if isinstance(st, dict) and st.get("hasCreateRequestToken"):
                            react_ok = True
                            fiber_token_ok = True
                            last_st = st
                            _log(
                                f"React/Castle 就绪(刷新后) · via={st.get('via')} · "
                                f"{time.time()-t_react:.1f}s"
                            )
                            break
                        page.wait_for_timeout(react_poll)
                except Exception as reload_err:
                    # 禁止 as re：会遮蔽 import re，后续 re.search 直接 UnboundLocalError
                    out["steps"].append(f"reload_err:{type(reload_err).__name__}")
            else:
                pr = timing_cfg["post_react_ms"]
                lo_pr, hi_pr = int(pr[0]), int(pr[1])
                if hi_pr > 0:
                    ms = random.randint(max(0, lo_pr), max(lo_pr, hi_pr))
                    page.wait_for_timeout(ms)
                    out["steps"].append(f"wait:post_react:{ms}ms")
            out["steps"].append(
                "page_loaded"
                + (":fiber_token" if fiber_token_ok else (":react" if react_ok else ":no_react"))
            )
            out["steps"].append(f"timing:{timing_cfg['name']}")

            # 实时刷新 action_id / state_tree（缓存过期 → signup 200 但无 set-cookie）
            cfg = _refresh_action_from_page(page, cfg, log=_log)
            out["action_id"] = (cfg.get("action_id") or "")[:24]
            out["steps"].append(f"action:{(cfg.get('action_id') or '')[:16]}")

            # 1) 同页 mint castle：纯 page.evaluate，禁止 click/type/鼠标交互
            pm = timing_cfg["pre_mint_ms"]
            lo_pm, hi_pm = int(pm[0]), int(pm[1])
            if hi_pm > 0:
                ms = random.randint(max(0, lo_pm), max(lo_pm, hi_pm))
                page.wait_for_timeout(ms)
                out["steps"].append(f"wait:pre_mint:{ms}ms")
            last_raw: Any = None
            mint_n = int(timing_cfg.get("mint_attempts") or 3)
            mint_args = mint_js_args()  # 默认 fiber-only，短 token 不外传
            t_mint = time.time()
            for attempt in range(1, mint_n + 1):
                # 每轮 mint 前再确认 fiber（Provider 晚挂）
                if attempt > 1 or not fiber_token_ok:
                    try:
                        st2 = page.evaluate(_FIBER_READY_JS)
                        if isinstance(st2, dict) and st2.get("hasCreateRequestToken"):
                            fiber_token_ok = True
                    except Exception:
                        pass
                raw = page.evaluate(_MINT_JS, mint_args)
                last_raw = raw
                if isinstance(raw, dict):
                    if raw.get("token"):
                        cand = str(raw["token"])
                        if is_castle_token_usable(cand):
                            castle = cand
                            out["castle_method"] = str(
                                raw.get("method") or "react_fiber"
                            )
                            if attempt > 1:
                                out["castle_method"] += f"_try{attempt}"
                            break
                        out["steps"].append(f"castle_short:{len(cand)}")
                    elif raw.get("error"):
                        out["steps"].append(
                            f"castle_try{attempt}:{_compact_log(raw.get('error'), 48)}"
                        )
                    elif raw.get("raw_len"):
                        out["steps"].append(f"castle_short:{raw.get('raw_len')}")
                bm = timing_cfg["between_mint_ms"]
                # fiber 空时多等：Provider 还在挂
                extra = 400 * attempt if not fiber_token_ok else attempt * 120
                wait_m = random.randint(int(bm[0]), int(bm[1])) + extra
                page.wait_for_timeout(wait_m)
            if not is_castle_token_usable(castle):
                dbg = ""
                if isinstance(last_raw, dict):
                    dbg = (
                        f" method={last_raw.get('method')} "
                        f"err={_compact_log(last_raw.get('error'), 60)}"
                    )
                out["error"] = (
                    f"same-session castle 过短/失败 len={len(castle or '')} "
                    f"min={MIN_CASTLE_LEN}{dbg}"
                )
                out["castle_len"] = len(castle or "")
                return out
            out["castle_len"] = len(castle)
            out["steps"].append(
                f"castle_ok:{out['castle_len']}:{out['castle_method']}"
            )
            _log(
                f"castle ok · {out['castle_len']} · "
                f"{out['castle_method']} · {time.time()-t_mint:.1f}s"
            )

            # 公共头：与页内 connect-es 一致（referer 用当前页 URL）
            # Accept-Language 跟随指纹区 locale，禁止写死 en-US
            page_url = page.url or f"{SITE}/sign-up"
            grpc_headers = {
                "content-type": "application/grpc-web+proto",
                "x-grpc-web": "1",
                "x-user-agent": "connect-es/2.1.1",
                "accept": "*/*",
                "accept-language": accept_language,
            }

            # Turnstile 并行预解：与发码/收码/验码重叠（本地 solver 通常 15–20s）
            ts_token = turnstile_token
            ts_holder: dict[str, Any] = {"token": None, "error": None, "t0": 0.0}
            ts_thread: Optional[threading.Thread] = None
            do_ts_parallel = (
                _ts_parallel_enabled()
                and not ts_token
                and callable(solve_turnstile)
            )

            def _ts_worker(sk: str) -> None:
                ts_holder["t0"] = time.time()
                try:
                    tok = solve_turnstile(sk)
                    ts_holder["token"] = tok
                except Exception as e:
                    ts_holder["error"] = str(e)

            if do_ts_parallel:
                sk = (cfg.get("site_key") or "0x4AAAAAAAhr9JGVDZbrZOo0").strip()
                _log("Turnstile 并行预解中…")
                ts_thread = threading.Thread(
                    target=_ts_worker, args=(sk,), daemon=True, name="ts-presolve"
                )
                ts_thread.start()
                out["steps"].append("turnstile_parallel:start")

            # 2) 发码 —— x.ai 2026-10 起改为 REST JSON，且要求 castleRequestToken
            #    （旧 grpc-web CreateEmailValidationCode 仍回 status 0 但不再发信）
            pc = timing_cfg["pre_code_ms"]
            lo_c, hi_c = int(pc[0]), int(pc[1])
            if hi_c > 0:
                page.wait_for_timeout(random.randint(max(0, lo_c), max(lo_c, hi_c)))
            json_headers = {
                "content-type": "application/json",
                "accept": "*/*",
                "accept-language": accept_language,
            }
            send_payload = {"email": email}
            if castle:
                send_payload["castleRequestToken"] = castle
            r1 = _page_text_post(
                page,
                f"{SITE}/api/auth/send-verification-code",
                json.dumps(send_payload),
                json_headers,
            )
            out["steps"].append(f"send_code:{r1['status']}")
            if r1.get("error"):
                out["error"] = f"send-verification-code fetch err: {r1['error']}"
                return out
            if r1["status"] != 200:
                out["error"] = (
                    f"send-verification-code HTTP {r1['status']} "
                    f"body={(r1.get('text') or '')[:120]!r}"
                )
                return out
            try:
                send_data = json.loads(r1.get("text") or "{}")
            except Exception:
                send_data = {}
            if isinstance(send_data, dict) and send_data.get("code"):
                out["error"] = (
                    "send-verification-code 被拒: "
                    f"{send_data.get('code')} {str(send_data.get('error') or '')[:80]}"
                )
                return out
            _log(f"发码 ok · {r1['status']}")

            # 3) 取验证码
            code = verification_code
            if not code and fetch_code:
                code = fetch_code(email)
            if not code:
                out["error"] = "no verification code"
                return out
            code = str(code).strip()
            out["code"] = code
            out["steps"].append(f"code:{code}")
            _log(f"验证码 {code}")

            # 4) 验码 —— REST /api/auth/sign-up/verify-email
            r2 = _page_text_post(
                page,
                f"{SITE}/api/auth/sign-up/verify-email",
                json.dumps({"email": email, "code": re.sub(r"\D", "", code)}),
                json_headers,
            )
            out["steps"].append(f"verify_code:{r2['status']}")
            if r2.get("error"):
                out["error"] = f"verify-email fetch err: {r2['error']}"
                return out
            try:
                verify_data = json.loads(r2.get("text") or "{}")
            except Exception:
                verify_data = {}
            if r2["status"] != 200 or (
                isinstance(verify_data, dict) and verify_data.get("code")
            ):
                out["error"] = (
                    f"verify-email 被拒: HTTP {r2['status']} "
                    f"{(r2.get('text') or '')[:120]}"
                )
                return out
            _log(f"验码 ok · {r2['status']}")

            # 5) 收 Turnstile：优先吃并行结果；并行已好则不再空等
            if ts_thread is not None:
                # 邮箱快时 solver 可能还没完；默认最多再等 150s
                # （慢代理下 CF 挑战 60~120s 常见，90s 会白白废掉一个已验证邮箱）
                try:
                    ts_wait = float(os.getenv("GROK_TS_WAIT_SEC") or "150")
                except ValueError:
                    ts_wait = 150.0
                ts_wait = max(30.0, min(ts_wait, 400.0))
                remain = max(1.0, ts_wait - (time.time() - (ts_holder.get("t0") or time.time())))
                ts_thread.join(timeout=remain)
                if ts_thread.is_alive():
                    out["error"] = "turnstile parallel timeout"
                    return out
                if ts_holder.get("token") and ts_holder["token"] != "CAPTCHA_FAIL":
                    ts_token = ts_holder["token"]
                    elapsed_ts = round(time.time() - float(ts_holder.get("t0") or t0), 1)
                    out["steps"].append(f"turnstile_parallel:ok:{elapsed_ts}s")
                    _log(f"Turnstile ok · 并行 {elapsed_ts}s")
                else:
                    err = ts_holder.get("error") or "empty"
                    out["steps"].append(f"turnstile_parallel:fail:{_compact_log(err, 40)}")
                    _log(f"Turnstile 并行失败，同步补解 · {_compact_log(err, 60)}")
                    ts_token = None
            if not ts_token and solve_turnstile:
                # 仅同步补解前做极短抖动
                pt = timing_cfg["pre_turnstile_ms"]
                lo, hi = int(pt[0]), int(pt[1])
                if hi > 0:
                    page.wait_for_timeout(random.randint(max(0, lo), max(lo, hi)))
                _log("Turnstile 同步求解…")
                t_ts = time.time()
                ts_token = solve_turnstile(cfg["site_key"])
                out["steps"].append(f"turnstile_sync:{round(time.time()-t_ts,1)}s")
            if not ts_token or ts_token == "CAPTCHA_FAIL":
                out["error"] = "turnstile fail"
                return out
            out["turnstile_len"] = len(ts_token)
            out["steps"].append("turnstile_ok")
            if "turnstile_parallel:ok" not in " ".join(out["steps"]):
                _log("Turnstile ok · 同步")

            # 提交前再铸一次 castle（更贴近点击 Create 瞬间）；fast 档几乎不空等
            ps = timing_cfg["pre_signup_ms"]
            lo_ps, hi_ps = int(ps[0]), int(ps[1])
            if hi_ps > 0:
                page.wait_for_timeout(random.randint(max(0, lo_ps), max(lo_ps, hi_ps)))
            raw3 = page.evaluate(_MINT_JS, mint_js_args())
            if isinstance(raw3, dict) and raw3.get("token"):
                cand = str(raw3["token"])
                if is_castle_token_usable(cand):
                    castle = cand
                    out["castle_method"] = (
                        str(raw3.get("method") or out["castle_method"]) + "+pre_submit"
                    )
                    out["castle_len"] = len(castle)
                    out["steps"].append(f"castle_refresh:{len(castle)}")

            # 6) signup —— 页内 fetch（同 cookie / 同 TLS / 同页 castle）
            if not cfg.get("action_id"):
                out["error"] = "missing next-action id"
                return out
            body = {
                "emailValidationCode": code,
                "createUserAndSessionRequest": {
                    "email": email,
                    "givenName": given,
                    "familyName": family,
                    "clearTextPassword": password,
                    "tosAcceptedVersion": "$undefined",
                },
                "turnstileToken": ts_token,
                "conversionId": conversion_id,
                "promptOnDuplicateEmail": True,
                "castleRequestToken": castle,
            }
            signup_headers = {
                "accept": "text/x-component",
                "content-type": "text/plain;charset=UTF-8",
                "next-router-state-tree": cfg["state_tree"],
                "next-action": cfg["action_id"],
                "accept-language": accept_language,
            }
            payload = json.dumps([body], ensure_ascii=False)

            def _read_sso_jar() -> tuple[str, str]:
                try:
                    cookies = ctx.cookies()
                except Exception:
                    cookies = []
                return _cookies_sso(cookies)

            def _signup_hard_fail(text_body: str) -> Optional[str]:
                """
                不可重试的业务错误。

                严禁在完整 RSC/JS 大包上做 "duplicate"+"email" 宽松匹配：
                成功响应对常夹带 i18n 文案（"Duplicate account"、
                "account already exists"、promptOnDuplicateEmail），
                会把好号误杀成 duplicate（23:56 批次 #1/#2）。
                """
                t = text_body or ""
                if not t:
                    return None
                # 验证码失效：字段名稳定，可在任意 body 上认
                if (
                    "invalid-validation" in t
                    or "Email validation code is invalid" in t
                    or "email:invalid" in t
                ):
                    return "email validation code invalid"

                # 大 body（>4KB）多半是 RSC 碎片 + i18n 字典，不当 hard fail
                # 真 duplicate 业务错误通常是短 E{...} / digest 包
                if len(t) > 4000:
                    return None

                low = t.lower()
                # 短错误体上的明确业务码
                hard_patterns = (
                    (r'"code"\s*:\s*"email_already[^"]*"', "duplicate email"),
                    (r"emailalreadyexists", "duplicate email"),
                    (r"email_already_exists", "duplicate email"),
                    (r"duplicate_email", "duplicate email"),
                    (r"email\s+is\s+already\s+registered", "duplicate email"),
                )
                for pat, label in hard_patterns:
                    if re.search(pat, low):
                        return label
                return None

            # signup 重试：
            # 1) 网络断流 Failed to fetch
            # 2) HTTP 200 但 body 无 set-cookie（#14 类：action 过期 / RSC digest 空响）
            # 重试策略：刷新 action_id + 重 mint castle（不重解 turnstile，验证码仍有效）
            try:
                max_signup_tries = max(1, min(5, int(os.getenv("GROK_SIGNUP_RETRIES") or "3")))
            except ValueError:
                max_signup_tries = 3
            r3: dict[str, Any] = {"status": 0, "error": "not_started", "text": ""}
            text = ""
            set_urls: list[str] = []
            for s_try in range(1, max_signup_tries + 1):
                if s_try > 1:
                    _log(f"signup 重试 #{s_try}/{max_signup_tries}")
                    out["steps"].append(f"signup_retry:{s_try}")
                    try:
                        # 短退避：1.0 / 1.6 / 2.2s …
                        page.wait_for_timeout(600 + s_try * 400)
                    except Exception:
                        time.sleep(0.6 + s_try * 0.4)
                    # action_id 过期时 server action 仍 200 但无 set-cookie → 必须刷新
                    try:
                        cfg = _refresh_action_from_page(page, cfg, log=_log)
                        if cfg.get("action_id"):
                            signup_headers["next-action"] = cfg["action_id"]
                            signup_headers["next-router-state-tree"] = cfg.get(
                                "state_tree"
                            ) or signup_headers.get("next-router-state-tree") or ""
                            out["action_id"] = (cfg.get("action_id") or "")[:24]
                            out["steps"].append(
                                f"action_refresh:{(cfg.get('action_id') or '')[:16]}"
                            )
                    except Exception as e:
                        out["steps"].append(f"action_refresh_err:{type(e).__name__}")
                    # 再 mint castle
                    try:
                        raw_r = page.evaluate(_MINT_JS, mint_js_args())
                        if isinstance(raw_r, dict) and raw_r.get("token"):
                            cand_r = str(raw_r["token"])
                            if is_castle_token_usable(cand_r):
                                castle = cand_r
                                body["castleRequestToken"] = castle
                                out["castle_len"] = len(castle)
                                out["steps"].append(f"castle_retry:{len(castle)}")
                    except Exception:
                        pass
                    payload = json.dumps([body], ensure_ascii=False)

                r3 = _page_text_post(
                    page,
                    f"{SITE}/sign-up",
                    payload,
                    signup_headers,
                )
                text = r3.get("text") or ""
                st = int(r3.get("status") or 0)
                out["signup_status"] = st
                out["signup_body_head"] = text[:800]
                if st:
                    out["steps"].append(f"signup:{st}")
                else:
                    out["steps"].append("signup:0")

                if r3.get("error"):
                    err_s = str(r3.get("error") or "")
                    out["steps"].append(f"signup_net:{_compact_log(err_s, 48)}")
                    _log(f"signup 网络失败 try#{s_try}: {_compact_log(err_s, 80)}")
                    # 非网络类不重试
                    if (
                        err_s
                        and "Failed to fetch" not in err_s
                        and "NetworkError" not in err_s
                        and "net::" not in err_s.lower()
                    ):
                        out["error"] = f"signup fetch err: {_compact_log(err_s, 100)}"
                        return out
                    if s_try >= max_signup_tries:
                        out["error"] = f"signup fetch err: {_compact_log(err_s, 100)}"
                        return out
                    continue

                # 落盘最近一次 body
                try:
                    dump = _BASE / "logs" / "same_session_last_signup_body.txt"
                    dump.write_text(text, encoding="utf-8", errors="ignore")
                    out["signup_body_dump"] = str(dump)
                except Exception:
                    pass

                # 先看 set-cookie / jar —— 成功体常夹 i18n「Duplicate account」
                set_urls = _extract_set_cookie_urls(text)
                out["set_cookie_urls"] = len(set_urls)
                if set_urls:
                    out["set_cookie_url0_len"] = len(set_urls[0])
                    out["set_cookie_url0_host"] = re.sub(
                        r"^https?://([^/]+).*$", r"\1", set_urls[0]
                    )
                    _log(f"signup {st} · castle={len(castle)} · set-cookie={len(set_urls)}")
                    break

                # body 无 URL 时先 peek jar（偶发 cookie 已写）
                s_peek, _ = _read_sso_jar()
                if s_peek:
                    out["steps"].append("signup:jar_after_empty_body")
                    _log(f"signup {st} · body 无 set-cookie 但 jar 已有 SSO")
                    break

                # 无 set-cookie 才判 hard fail（短错误体）
                hard = _signup_hard_fail(text)
                if hard:
                    out["error"] = hard
                    out["steps"].append(f"signup_hard:{hard}")
                    return out

                # #14：200 + RSC digest / 空业务响 → 重试
                digest_m = re.search(r'"digest"\s*:\s*"(\d+)"', text)
                digest_note = f" digest={digest_m.group(1)}" if digest_m else ""
                # RSC 里真正的业务错误（body 很长，前 240 字符看不到）
                # 注意跳过 `$undefined` 这类 flight 引用占位
                err_m = re.search(r'"error"\s*:\s*"([^"]{0,240})"', text or "")
                biz_err = err_m.group(1).strip() if err_m else ""
                if biz_err.startswith("$"):
                    biz_err = ""
                out["steps"].append(f"signup_no_setcookie:try{s_try}")
                _log(
                    f"signup {st} 无 set-cookie · try#{s_try}/{max_signup_tries}"
                    f"{digest_note}"
                    + (f" · 业务错误={biz_err}" if biz_err else " · 无业务错误(疑似 action 过期)")
                )
                # 有明确业务错误时重试没意义，而且验证码已被消耗：
                # 继续重试只会得到 email:invalid-validation-code，白烧一个邮箱。
                if biz_err:
                    out["error"] = f"signup 被拒: {biz_err}"
                    out["steps"].append("signup_biz_error")
                    return out
                if s_try >= max_signup_tries:
                    out["error"] = (
                        f"signup {st} 但 body 无 set-cookie URL "
                        f"body={text[:200]}"
                    )
                    return out
                # 继续下一轮
                continue

            # 跟随 set-cookie —— 必须同浏览器会话跟完整嵌套链
            # 链：grokipedia → grokusercontent → grok.com → auth.x.ai → accounts
            # 独立 curl 无注册会话 cookie → 400/auth-error，废的

            def _page_alive() -> bool:
                """浏览器/页已关时禁止再 goto/wait，避免 TargetClosedError 冒泡成整号异常。"""
                try:
                    if page is None or page.is_closed():
                        return False
                except Exception:
                    return False
                try:
                    if ctx is not None and getattr(ctx, "browser", None) is not None:
                        br = ctx.browser
                        if br is not None and not br.is_connected():
                            return False
                except Exception:
                    pass
                return True

            def _safe_page_wait(ms: int = 200) -> None:
                if _page_alive():
                    try:
                        page.wait_for_timeout(ms)
                        return
                    except Exception:
                        pass
                time.sleep(max(0.05, (ms or 200) / 1000.0))

            def _follow_set_cookie(urls: list[str], tag: str = "set_cookie") -> tuple[str, str]:
                """
                最短路径（已验证有效）：
                1) 完整 T-chunk URL
                2) context.request.get（与 Chrome 同 cookie 罐，自动跟 302）
                3) 失败再 page.goto 一次入口
                禁止：独立 curl、禁止手动 5 站 hop
                浏览器已关：只读 jar，不再 goto/evaluate（修 TargetClosedError）
                """
                if not urls:
                    return "", ""
                entry = urls[0]
                chain = _expand_set_cookie_chain(entry)
                hosts = [re.sub(r"^https?://([^/]+).*$", r"\1", x) for x in chain]
                out["set_cookie_chain"] = hosts
                out["set_cookie_url0_len"] = len(entry)
                short_hosts = "→".join(h.split(".")[0] for h in hosts[:5]) if hosts else "?"

                # 先 peek jar：有时 set-cookie 已同步写进 context，可省一次 request
                s1, s2 = _read_sso_jar()
                if s1:
                    out["steps"].append(f"{tag}:jar_peek_ok")
                    _log(f"cookie 链完成 · jar 直取 · {short_hosts}")
                    return s1, s2 or s1

                # --- 新版 cookie-chain：必须真·浏览器导航，且要抢在 token 被消耗前 ---
                # 用 ctx.request 先打一发会被 CF 403，而且这个 q 是一次性的：
                # 先打非浏览器请求 = 把链烧掉，后面 goto/hops 全 400。
                if "cookie-chain?q=" in entry and _page_alive():
                    out["steps"].append(f"{tag}:chain_goto_first")
                    try:
                        page.goto(entry, wait_until="domcontentloaded", timeout=45000)
                        out["steps"].append(f"{tag}:chain_goto_ok")
                    except Exception as e_cg:
                        out["steps"].append(f"{tag}:chain_goto_err:{type(e_cg).__name__}")
                        _log(f"cookie-chain 导航失败 · {_compact_log(e_cg, 80)}")
                    # 链页会用 JS 依次走 hop 并落 cookie：多等一会儿
                    for _ in range(40):
                        s1, s2 = _read_sso_jar()
                        if s1:
                            out["steps"].append(f"{tag}:chain_goto_jar")
                            _log(f"cookie 链完成 · chain 导航 · sso={len(s1)}")
                            return s1, s2 or s1
                        _safe_page_wait(300)
                    out["steps"].append(f"{tag}:chain_goto_no_sso")

                # --- 旧路径：context.request 共享 cookie 罐 ---
                req_status: Any = None
                closed_mid = False
                try:
                    # 超时收紧：有 sso 时通常几秒内落 jar
                    resp = ctx.request.get(entry, timeout=25000, max_redirects=15)
                    req_status = resp.status
                    out["steps"].append(f"{tag}:req:{resp.status}")
                except Exception as e:
                    en = type(e).__name__
                    out["steps"].append(f"{tag}:req_err:{en}")
                    req_status = f"err:{en}"
                    elow = str(e).lower()
                    if (
                        "targetclosed" in en.lower()
                        or "has been closed" in elow
                        or "target page" in elow
                        or "browser has been closed" in elow
                    ):
                        closed_mid = True

                s1, s2 = _read_sso_jar()
                if s1:
                    out["steps"].append(f"{tag}:jar_ok")
                    # 403 常见但 jar 已有 sso，不算失败，不吓人
                    note = f"http={req_status}" if req_status not in (200, 302, 303, 307, 308) else "ok"
                    _log(f"cookie 链完成 · {short_hosts} · {note}")
                    return s1, s2 or s1

                # request 后短轮询（约 1.2s），常比立刻 page.goto 更稳更快
                for _ in range(6):
                    _safe_page_wait(200)
                    s1, s2 = _read_sso_jar()
                    if s1:
                        out["steps"].append(f"{tag}:jar_poll_ok")
                        _log(f"cookie 链完成 · 短轮询 · {short_hosts}")
                        return s1, s2 or s1

                # 浏览器已关：禁止 page.goto，避免二次 TargetClosed 炸整号
                if closed_mid or not _page_alive():
                    out["steps"].append(f"{tag}:browser_closed")
                    _log(
                        f"cookie 链未落 jar · {short_hosts} · http={req_status}"
                        f" · 浏览器已关，跳过 page.goto"
                    )
                    try:
                        out["cookie_names"] = [
                            f"{c.get('name')}@{c.get('domain')}"
                            for c in (ctx.cookies() or [])
                        ][:40]
                    except Exception:
                        pass
                    return "", ""

                _log(f"cookie 链未落 jar · {short_hosts} · http={req_status}，改 page.goto")

                # --- 辅：page.goto 入口一次，浏览器自己跟 302 ---
                try:
                    page.goto(entry, wait_until="commit", timeout=45000)
                    out["steps"].append(f"{tag}:goto")
                except Exception as e:
                    out["steps"].append(f"{tag}:goto_err:{type(e).__name__}")
                    _log(f"page.goto 跟链失败 · {_compact_log(e, 80)}")
                    # 最后：location 赋值（页仍活才试）
                    if _page_alive():
                        try:
                            page.evaluate(
                                """(u) => { window.location.href = u; return true; }""",
                                entry,
                            )
                            page.wait_for_load_state("domcontentloaded", timeout=30000)
                            out["steps"].append(f"{tag}:location")
                        except Exception as e2:
                            out["steps"].append(f"{tag}:loc_err:{type(e2).__name__}")

                # 最多约 2.4s 轮询 jar
                for _ in range(8):
                    s1, s2 = _read_sso_jar()
                    if s1:
                        out["steps"].append(f"{tag}:jar_ok")
                        _log(f"cookie 链完成 · page.goto · {short_hosts}")
                        return s1, s2 or s1
                    _safe_page_wait(300)

                # --- cookie-chain 的 hops：必须由同一浏览器会话逐个访问 ---
                hops = _cookie_chain_hops(entry)
                if hops:
                    out["steps"].append(f"{tag}:hops:{len(hops)}")
                    _log(f"cookie 链未落 sso · 逐个访问 {len(hops)} 个 hop")
                    for hi, hop in enumerate(hops[:8]):
                        s1, _ = _read_sso_jar()
                        if s1 or not _page_alive():
                            break
                        try:
                            page.goto(hop, wait_until="commit", timeout=25000)
                            out["steps"].append(f"{tag}:hop{hi}")
                        except Exception as e_hop:
                            out["steps"].append(
                                f"{tag}:hop{hi}_err:{type(e_hop).__name__}"
                            )
                            continue
                        for _ in range(10):
                            s1, _ = _read_sso_jar()
                            if s1:
                                break
                            _safe_page_wait(200)
                    s1, s2 = _read_sso_jar()
                    if s1:
                        out["steps"].append(f"{tag}:hops_ok")
                        _log(f"cookie 链完成 · hops · sso={len(s1)}")
                        return s1, s2 or s1

                try:
                    out["cookie_names"] = [
                        f"{c.get('name')}@{c.get('domain')}"
                        for c in (ctx.cookies() or [])
                    ][:40]
                except Exception:
                    pass
                return "", ""

            sso = sso_rw = ""
            if set_urls:
                sso, sso_rw = _follow_set_cookie(set_urls)
            else:
                # 重试循环里 jar_after_empty_body 已确认 jar 有 SSO
                sso, sso_rw = _read_sso_jar()
                if sso:
                    out["steps"].append("set_cookie:skip_jar_ready")
                    _log("cookie 链跳过 · jar 已有 SSO")
                else:
                    out["error"] = (
                        f"signup {out.get('signup_status') or 200} 但 body 无 set-cookie URL "
                        f"body={text[:200]}"
                    )
                    return out

            if not sso:
                # 再短等 jar（约 1.5s）；页已关用 sleep，禁止 wait_for_timeout 抛 TargetClosed
                for _ in range(5):
                    sso, sso_rw = _read_sso_jar()
                    if sso:
                        break
                    try:
                        if page is not None and not page.is_closed():
                            page.wait_for_timeout(300)
                        else:
                            time.sleep(0.3)
                    except Exception:
                        time.sleep(0.3)

            if not sso:
                _st = out.get("signup_status")
                if _st is None and isinstance(r3, dict):
                    _st = r3.get("status")
                out["error"] = (
                    f"no sso after set-cookie follow "
                    f"status={_st} set_urls={len(set_urls)} "
                    f"url0_len={out.get('set_cookie_url0_len')} "
                    f"cookies={out.get('cookie_names')}"
                )
                return out

            out["sso"] = sso
            out["sso_rw"] = sso_rw
            out["sso_len"] = len(sso)
            out["ok"] = True
            out["steps"].append("sso_ok")
            out["page_url"] = page_url
            _log(f"SSO 到手 · {len(sso)}")
        finally:
            # 关 context；池化时不关 camoufox 进程
            try:
                if ctx is not None:
                    ctx.close()
            except Exception:
                pass
            if camoufox_cm is not None and not from_pool:
                try:
                    camoufox_cm.__exit__(None, None, None)
                except Exception:
                    pass
                # 整机关闭后才 force 清 loop
                _clear_thread_event_loop(force=True)
            # 池路径：browser/Playwright loop 仍存活，禁止 force 清。
            # 之前这里 force 清会把 thread-local _running_loop 摘掉，
            # 下号冷启/复用时回调炸：ProactorEventLoop is not the running loop。
            pw = out.pop("_pw", None)
            if pw is not None:
                try:
                    pw.stop()
                except Exception:
                    pass
                _clear_thread_event_loop(force=True)
    except Exception as e:
        out["error"] = f"same_session 异常: {e}"
        out["steps"].append(f"exc:{e}")
        # 异常路径也尽量收尾浏览器资源
        try:
            if ctx is not None:
                ctx.close()
        except Exception:
            pass
        # 异常时若还握着 camoufox_cm：关掉并 force 清；
        # 若已入池（from_pool / cm 已移交），不要 force 清 running loop
        if camoufox_cm is not None and not from_pool:
            try:
                camoufox_cm.__exit__(None, None, None)
            except Exception:
                pass
            _clear_thread_event_loop(force=True)
        pw = out.pop("_pw", None)
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass
            _clear_thread_event_loop(force=True)
    finally:
        out["elapsed_s"] = round(time.time() - t0, 2)
        # 恢复业务代理环境（多账号循环下一号还要读 GROK_PROXY）
        for k, v in (_saved_biz or {}).items():
            if v:
                os.environ[k] = v
        # 可选清理临时 profile
        if fresh_profile and (os.getenv("GROK_SAME_SESSION_KEEP_PROFILE") or "0") not in (
            "1",
            "true",
            "on",
        ):
            try:
                if profile_dir and profile_dir.exists() and "same_session_profiles" in str(
                    profile_dir
                ):
                    shutil.rmtree(profile_dir, ignore_errors=True)
            except Exception:
                pass

    return out
