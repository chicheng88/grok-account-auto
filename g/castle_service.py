"""
Castle request token mint for xAI sign-up.

Real Chrome sign-up body carries:
  conversionId + castleRequestToken (Castle SDK createRequestToken)
HTTP path without them → botFlag castle_token:no_token → false_clean → device invalid_grant.

Critical quality gate:
  Real page Castle tokens are ~16k chars (react_fiber / page provider).
  npm @castleio/castle-js often yields ~700 chars → server marks invalid_token.
  REJECT any token shorter than MIN_CASTLE_LEN.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

CASTLE_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
SITE = "https://accounts.x.ai"
# 真 Chrome 抓包 / 成功 fiber mint 约 16k；npm 短 token ~700 必 invalid_token
MIN_CASTLE_LEN = int((os.getenv("GROK_CASTLE_MIN_LEN") or "4000").strip() or "4000")
_BASE = Path(__file__).resolve().parents[1]
_LOCK = threading.Lock()
_LAST_MINT_TS = 0.0
_LAST_ERR = ""


def new_conversion_id() -> str:
    return str(uuid.uuid4())


def castle_mint_enabled() -> bool:
    """
    GROK_CASTLE_MINT:
      1/true/on  → try browser mint
      0/false/off → skip browser, still send conversionId only (default)
    """
    raw = (os.getenv("GROK_CASTLE_MINT") or "0").strip().lower()
    return raw not in ("0", "false", "off", "no", "none")


def castle_headless() -> bool:
    # 默认真无头，不弹窗；GROK_CASTLE_HEADLESS=0 才有界面
    raw = (os.getenv("GROK_CASTLE_HEADLESS") or "1").strip().lower()
    return raw not in ("0", "false", "off", "no", "gui", "headed")


def last_error() -> str:
    return _LAST_ERR or ""


def is_castle_token_usable(token: Optional[str], *, min_len: int | None = None) -> bool:
    t = (token or "").strip()
    need = MIN_CASTLE_LEN if min_len is None else int(min_len)
    return len(t) >= need


def _accept_token(
    out: dict[str, Any],
    token: str,
    method: str,
    *,
    t0: float,
    debug_extra: Optional[dict] = None,
) -> bool:
    """Return True and fill out if token passes length gate."""
    global _LAST_ERR, _LAST_MINT_TS
    castle = (token or "").strip()
    out.setdefault("debug", {})
    if debug_extra:
        out["debug"].update(debug_extra)
    out["debug"][f"{method}_len"] = len(castle)
    if not is_castle_token_usable(castle):
        out["debug"][f"{method}_reject"] = (
            f"token too short len={len(castle)} min={MIN_CASTLE_LEN}"
        )
        return False
    out["ok"] = True
    out["castle"] = castle
    out["castle_len"] = len(castle)
    out["method"] = method
    out["elapsed_s"] = round(time.time() - t0, 2)
    _LAST_ERR = ""
    _LAST_MINT_TS = time.time()
    return True


# Page-side mint: **fiber only** (React CastleProvider ~12k–16k).
# CDN / window.Castle / npm 短 token（~1.7k–2.2k）一律不用——服务端 invalid_token。
# GROK_CASTLE_MINT_MODE=hybrid 才允许 CDN 兜底（调试用，默认 fiber）。
def castle_mint_mode() -> str:
    raw = (os.getenv("GROK_CASTLE_MINT_MODE") or "fiber").strip().lower()
    if raw in ("hybrid", "cdn", "fallback", "all"):
        return "hybrid"
    return "fiber"


_MINT_JS = r"""
async (args) => {
  // args: {pk, mode, minLen}  兼容旧调用只传 pk 字符串
  const pk = (typeof args === 'string') ? args : (args && args.pk);
  const mode = (typeof args === 'object' && args && args.mode) ? String(args.mode) : 'fiber';
  const minLen = (typeof args === 'object' && args && args.minLen) ? Number(args.minLen) : 4000;
  const out = {attempts: [], ok: false, token: null, method: null, error: null, mode: mode};

  function walkFiber(node, depth, bag) {
    if (!node || depth > 60) return;
    try {
      const props = node.memoizedProps || node.pendingProps || {};
      const val = props.value || props;
      if (val && typeof val.createRequestToken === 'function') {
        bag.fn = val.createRequestToken;
        bag.found = true;
        bag.via = 'value.createRequestToken';
      }
      if (props.createRequestToken && typeof props.createRequestToken === 'function') {
        bag.fn = props.createRequestToken;
        bag.found = true;
        bag.via = 'props.createRequestToken';
      }
      // CastleProvider 常见：value = { createRequestToken, ... }
      if (!bag.fn && val && typeof val === 'object') {
        for (const k of Object.keys(val)) {
          try {
            if (k === 'createRequestToken' && typeof val[k] === 'function') {
              bag.fn = val[k]; bag.found = true; bag.via = 'value[createRequestToken]';
            }
          } catch (e) {}
        }
      }
    } catch (e) {}
    if (bag.fn) return;
    if (node.child) walkFiber(node.child, depth + 1, bag);
    if (!bag.fn && node.sibling) walkFiber(node.sibling, depth + 1, bag);
  }

  async function tryFiber(label) {
    const bag = {found: false, fn: null, via: null};
    try {
      if (window.__castleCreate && typeof window.__castleCreate === 'function') {
        bag.fn = window.__castleCreate;
        bag.found = true;
        bag.via = 'cache';
      }
      if (!bag.fn) {
        const all = document.querySelectorAll('*');
        // 优先扫根容器，再扫全树（CastleProvider 通常挂在顶层）
        const roots = [];
        for (const el of [document.documentElement, document.body, document.getElementById('root'), document.getElementById('__next')].filter(Boolean)) {
          roots.push(el);
        }
        for (const el of all) roots.push(el);
        const seen = new Set();
        for (const el of roots) {
          if (!el || seen.has(el)) continue;
          seen.add(el);
          const keys = Object.keys(el);
          for (const k of keys) {
            if (k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance')
                || k.startsWith('__reactContainer')) {
              walkFiber(el[k], 0, bag);
              if (bag.fn) break;
            }
          }
          if (bag.fn) break;
        }
      }
      if (!bag.fn) {
        out.attempts.push({method: label || 'react_fiber', ok: false, error: 'no createRequestToken in fiber', found: bag.found});
        return null;
      }
      window.__castleCreate = bag.fn;
      const t = await bag.fn();
      out.attempts.push({
        method: label || 'react_fiber',
        ok: !!t,
        len: (t || '').length,
        via: bag.via,
      });
      return t || null;
    } catch (e) {
      out.attempts.push({method: label || 'react_fiber', ok: false, error: String(e && e.message || e)});
      return null;
    }
  }

  async function tryWindowCastle() {
    try {
      if (window.Castle && typeof window.Castle.createRequestToken === 'function') {
        const t = await window.Castle.createRequestToken();
        out.attempts.push({method: 'window.Castle', ok: !!t, len: (t || '').length});
        return t || null;
      }
      out.attempts.push({method: 'window.Castle', ok: false, error: 'missing'});
      return null;
    } catch (e) {
      out.attempts.push({method: 'window.Castle', ok: false, error: String(e && e.message || e)});
      return null;
    }
  }

  async function tryOfficialCdn() {
    try {
      await new Promise((resolve, reject) => {
        if (window.Castle && typeof window.Castle.createRequestToken === 'function') {
          resolve();
          return;
        }
        const s = document.createElement('script');
        s.src = 'https://cdn.castle.io/v2/castle.js';
        s.async = true;
        s.onload = resolve;
        s.onerror = () => reject(new Error('castle cdn load fail'));
        document.head.appendChild(s);
        setTimeout(() => reject(new Error('castle cdn timeout')), 15000);
      });
      if (!window.Castle) {
        out.attempts.push({method: 'cdn.castle.io', ok: false, error: 'Castle global missing'});
        return null;
      }
      if (typeof window.Castle.configure === 'function') {
        try { window.Castle.configure({pk}); } catch (e) {}
      }
      let t = null;
      if (typeof window.Castle.createRequestToken === 'function') {
        t = await window.Castle.createRequestToken();
      } else if (window.Castle.default && typeof window.Castle.default.createRequestToken === 'function') {
        try { window.Castle.default.configure({pk}); } catch (e) {}
        t = await window.Castle.default.createRequestToken();
      }
      out.attempts.push({method: 'cdn.castle.io', ok: !!t, len: (t || '').length});
      return t || null;
    } catch (e) {
      out.attempts.push({method: 'cdn.castle.io', ok: false, error: String(e && e.message || e)});
      return null;
    }
  }

  // 默认 fiber-only：多轮 fiber，绝不吃 CDN/npm 短 token
  let token = null;
  let method = 'react_fiber';
  for (let i = 0; i < 3; i++) {
    const label = i === 0 ? 'react_fiber' : ('react_fiber_r' + i);
    const t = await tryFiber(label);
    if (t && t.length >= minLen) {
      token = t;
      method = label;
      break;
    }
    if (t && (!token || t.length > token.length)) {
      token = t;
      method = label;
    }
    if (i < 2) await new Promise(r => setTimeout(r, 800 + i * 400));
  }

  // hybrid 调试：fiber 仍不够长才碰 window/CDN（生产默认不开）
  if (mode === 'hybrid' && (!token || token.length < minLen)) {
    const tw = await tryWindowCastle();
    if (tw && tw.length > (token ? token.length : 0)) {
      token = tw;
      method = 'window.Castle';
    }
    if (!token || token.length < minLen) {
      const tc = await tryOfficialCdn();
      if (tc && tc.length > (token ? token.length : 0)) {
        token = tc;
        method = 'cdn.castle.io';
      }
    }
    // CDN 后再试一次 fiber（hydration）
    await new Promise(r => setTimeout(r, 1200));
    const t2 = await tryFiber('react_fiber_post_cdn');
    if (t2 && t2.length > (token ? token.length : 0)) {
      token = t2;
      method = 'react_fiber_post_cdn';
    }
  }

  // 短 token 直接当失败（调用方还会二次门禁）
  const usable = !!(token && token.length >= minLen);
  out.ok = usable;
  out.token = usable ? token : null;
  out.method = method;
  out.len = token ? token.length : 0;
  out.raw_len = token ? token.length : 0;
  if (!token) {
    out.error = mode === 'fiber'
      ? 'fiber mint failed (no createRequestToken / empty)'
      : 'all preferred mint methods failed';
  } else if (!usable) {
    out.error = 'fiber/token too short len=' + token.length + ' min=' + minLen;
    // 不把短 token 往外传，避免 signup 带 invalid_token
    out.token = null;
    out.ok = false;
  }
  out.page = {
    href: location.href,
    title: document.title,
    hasEnableCastle: (document.documentElement.innerHTML || '').includes('enableCastle'),
    hasPk: (document.documentElement.innerHTML || '').includes('castlePk'),
  };
  return out;
}
"""


def mint_js_args() -> dict[str, Any]:
    """page.evaluate(_MINT_JS, mint_js_args()) 统一入参。"""
    return {
        "pk": CASTLE_PK,
        "mode": castle_mint_mode(),
        "minLen": MIN_CASTLE_LEN,
    }


def mint_castle_from_browser(
    *,
    timeout_s: int = 70,
    headless: Optional[bool] = None,
    proxy: Optional[dict[str, Any]] = None,
    user_agent: Optional[str] = None,
) -> dict[str, Any]:
    """
    Open accounts.x.ai/sign-up in real Chrome, mint via page CastleProvider.
    Rejects short/npm-style tokens (invalid_token on server).

    proxy: Playwright proxy dict ({"server": "http://host:port", ...})，必须与
        后续 curl_cffi 走同一出口，否则服务端会把发码判成「换会话」而静默丢弃。
    user_agent: 覆盖 UA（无头 Chrome 默认 UA 带 HeadlessChrome，会被 CF 拦）。
    返回结果额外带 cookies / user_agent：发码接口要求 Castle token 与页面
    会话 cookie 同时存在，HTTP 侧要复用这份 cookie。
    """
    global _LAST_ERR, _LAST_MINT_TS
    conversion_id = new_conversion_id()
    out: dict[str, Any] = {
        "ok": False,
        "castle": None,
        "conversion_id": conversion_id,
        "method": None,
        "error": None,
        "elapsed_s": 0.0,
        "castle_len": 0,
        "min_len": MIN_CASTLE_LEN,
        "cookies": {},
        "user_agent": "",
        "debug": {},
    }
    if headless is None:
        headless = castle_headless()

    t0 = time.time()
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        out["error"] = f"playwright 不可用: {e}"
        _LAST_ERR = out["error"]
        out["elapsed_s"] = round(time.time() - t0, 2)
        return out

    profile = _BASE / "logs" / f"castle_mint_{uuid.uuid4().hex[:8]}"
    profile.mkdir(parents=True, exist_ok=True)
    out["profile"] = str(profile)

    try:
        with sync_playwright() as p:
            args = [
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-dev-shm-usage",
                "--window-size=1365,900",
            ]
            if headless:
                args.append("--headless=new")
            launch_kwargs: dict[str, Any] = dict(
                user_data_dir=str(profile),
                channel="chrome",
                headless=bool(headless),
                viewport={"width": 1365, "height": 900},
                locale="en-US",
                timezone_id="America/New_York",
                args=args,
            )
            if user_agent:
                launch_kwargs["user_agent"] = user_agent
            if proxy:
                launch_kwargs["proxy"] = proxy
            try:
                ctx = p.chromium.launch_persistent_context(**launch_kwargs)
            except Exception as launch_err:
                # 没装 Chrome 时退回 Playwright 自带 chromium，别整条链路直接失败
                out["debug"]["channel_fallback"] = str(launch_err)[:160]
                launch_kwargs.pop("channel", None)
                ctx = p.chromium.launch_persistent_context(**launch_kwargs)
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                page.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                    "Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});"
                    "window.chrome = window.chrome || {runtime: {}};"
                )
                nav_timeout = min(90000, max(30000, int(timeout_s) * 1000))
                page.goto(
                    f"{SITE}/sign-up",
                    wait_until="domcontentloaded",
                    timeout=nav_timeout,
                )
                # 等 React + CastleProvider 挂载（fiber mint 需要）
                try:
                    page.wait_for_load_state("networkidle", timeout=20000)
                except Exception:
                    pass
                page.wait_for_timeout(6000)

                # 轻交互：触发更多指纹/hydration
                try:
                    page.mouse.move(120, 160)
                    page.mouse.wheel(0, 200)
                    page.wait_for_timeout(800)
                    # 点一下邮箱框若存在
                    email = page.locator('input[type="email"], input[name="email"]').first
                    if email.count() > 0:
                        email.click(timeout=2000)
                        page.wait_for_timeout(500)
                except Exception:
                    pass

                raw = page.evaluate(_MINT_JS, mint_js_args())
                out["debug"]["page_result"] = {
                    k: raw.get(k)
                    for k in ("ok", "method", "len", "error", "attempts", "page", "mode", "raw_len")
                    if isinstance(raw, dict)
                } if isinstance(raw, dict) else {"raw_type": type(raw).__name__}

                if isinstance(raw, dict) and raw.get("token"):
                    method = str(raw.get("method") or "react_fiber")
                    if _accept_token(
                        out,
                        str(raw["token"]),
                        method,
                        t0=t0,
                        debug_extra={"attempts": raw.get("attempts"), "mode": raw.get("mode")},
                    ):
                        return out
                    # too short — keep trying longer wait + fiber again
                    out["debug"]["first_token_rejected_len"] = len(str(raw["token"]))
                elif isinstance(raw, dict) and raw.get("raw_len"):
                    out["debug"]["first_token_rejected_len"] = raw.get("raw_len")

                # retry after more wait (slow hydration)
                page.wait_for_timeout(4000)
                try:
                    page.mouse.move(240, 300)
                except Exception:
                    pass
                raw2 = page.evaluate(_MINT_JS, mint_js_args())
                out["debug"]["retry_result"] = {
                    k: raw2.get(k)
                    for k in ("ok", "method", "len", "error", "attempts")
                    if isinstance(raw2, dict)
                } if isinstance(raw2, dict) else {}
                if isinstance(raw2, dict) and raw2.get("token"):
                    method = str(raw2.get("method") or "react_fiber")
                    if _accept_token(
                        out,
                        str(raw2["token"]),
                        method + ("_retry" if not method.endswith("retry") else ""),
                        t0=t0,
                        debug_extra={"retry_attempts": raw2.get("attempts"), "mode": raw2.get("mode")},
                    ):
                        return out
                    out["debug"]["retry_token_rejected_len"] = len(str(raw2["token"]))
                elif isinstance(raw2, dict) and raw2.get("raw_len"):
                    out["debug"]["retry_token_rejected_len"] = raw2.get("raw_len")

                # 汇总失败原因
                lens = []
                for key in ("page_result", "retry_result"):
                    block = out["debug"].get(key) or {}
                    if block.get("len"):
                        lens.append(block["len"])
                    elif block.get("raw_len"):
                        lens.append(block["raw_len"])
                if lens:
                    out["error"] = (
                        f"castle fiber token too short (got {lens}, min={MIN_CASTLE_LEN}); "
                        f"mode={castle_mint_mode()} — CDN/npm short tokens disabled"
                    )
                else:
                    err = None
                    if isinstance(raw, dict):
                        err = raw.get("error")
                    if isinstance(raw2, dict) and not err:
                        err = raw2.get("error")
                    out["error"] = err or "castle mint failed (no usable token)"
                _LAST_ERR = out["error"]
            finally:
                # 发码接口把 Castle token 和页面会话绑定：必须带回 cookie/UA
                try:
                    out["cookies"] = {c["name"]: c["value"] for c in ctx.cookies()}
                except Exception:
                    out["cookies"] = {}
                try:
                    ua_now = page.evaluate("() => navigator.userAgent")
                    if ua_now:
                        out["user_agent"] = str(ua_now)
                except Exception:
                    out["user_agent"] = user_agent or ""
                try:
                    ctx.close()
                except Exception:
                    pass
                # 每号一次 mint 会留下一个 user-data-dir，及时清掉防止 logs 膨胀
                try:
                    import shutil as _shutil

                    _shutil.rmtree(str(profile), ignore_errors=True)
                except Exception:
                    pass
    except Exception as e:
        out["error"] = f"castle mint 异常: {e}"
        _LAST_ERR = out["error"]

    out["elapsed_s"] = round(time.time() - t0, 2)
    return out


def mint_signup_signals(
    *,
    want_castle: Optional[bool] = None,
    timeout_s: int = 70,
) -> dict[str, Any]:
    """
    Produce fields for sign-up body.
    Always returns conversion_id.
    castle only when mint enabled AND token passes MIN_CASTLE_LEN.
    Thread-safe (serializes browser mint).
    """
    conversion_id = new_conversion_id()
    result: dict[str, Any] = {
        "conversion_id": conversion_id,
        "castle": None,
        "castle_ok": False,
        "method": None,
        "error": None,
        "elapsed_s": 0.0,
        "castle_len": 0,
        "min_len": MIN_CASTLE_LEN,
    }
    do_castle = castle_mint_enabled() if want_castle is None else bool(want_castle)
    if not do_castle:
        result["error"] = "castle mint disabled"
        return result

    with _LOCK:
        minted = mint_castle_from_browser(timeout_s=timeout_s)
    result["conversion_id"] = minted.get("conversion_id") or conversion_id
    result["elapsed_s"] = minted.get("elapsed_s") or 0.0
    result["method"] = minted.get("method")
    castle = minted.get("castle")
    if minted.get("ok") and is_castle_token_usable(castle):
        result["castle"] = castle
        result["castle_ok"] = True
        result["castle_len"] = len(castle or "")
    else:
        # 绝不把短 token 当成功交给注册
        if castle and not is_castle_token_usable(castle):
            result["error"] = (
                minted.get("error")
                or f"castle too short len={len(castle)} min={MIN_CASTLE_LEN}"
            )
            result["castle_len"] = len(castle)
        else:
            result["error"] = minted.get("error") or "castle mint failed"
        result["debug"] = minted.get("debug")
    return result
