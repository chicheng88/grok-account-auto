from __future__ import annotations

import json
import struct
import time
from typing import Optional, Dict, Any

from curl_cffi import requests

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# grok.com 的 auth_mgmt 服务（grpc-web / connect）
GROK_AUTH_BASE = "https://grok.com"
ACCOUNTS_AUTH_BASE = "https://accounts.x.ai"

# 设置项名称（前端 /user-feature-controls-static?always_show_nsfw_content=… 同源）
NSFW_FLAG = "always_show_nsfw_content"

# 关键：这些 RPC 即使失败也返回 HTTP 200，真正结果在 grpc-status / grpc-message，
# 所以「HTTP 200 == 成功」是错的（曾导致 NSFW 假成功）。
_GRPC_OK = (None, "", "0")


def grpc_frame(payload: bytes = b"") -> bytes:
    """grpc-web 帧头：1 字节压缩位 + 4 字节大端长度。"""
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb_len_field(field_no: int, payload: bytes) -> bytes:
    """protobuf: (field_no, wire type 2) + len + payload"""
    return _varint((field_no << 3) | 2) + _varint(len(payload)) + payload


def pb_varint_field(field_no: int, value: int) -> bytes:
    return _varint(field_no << 3) + _varint(value)


def _status_ok(status_code: int, grpc_status: Optional[str]) -> bool:
    return status_code == 200 and (grpc_status or "0") in _GRPC_OK


def _decode_grpc_message(body: bytes) -> bytes:
    """从 grpc-web 响应体里取出第一条消息（去掉 5 字节帧头）。"""
    if len(body) >= 5 and body[0] in (0, 1):
        try:
            ln = struct.unpack(">I", body[1:5])[0]
        except Exception:
            return b""
        if 5 + ln <= len(body):
            return body[5 : 5 + ln]
    return b""


class NsfwSettingsService:
    """开启 NSFW 相关设置（线程安全，无全局状态）。"""

    def __init__(
        self,
        cf_clearance: str = "",
        proxies: Optional[Dict[str, str]] = None,
    ):
        self.cf_clearance = (cf_clearance or "").strip()
        # 关键：注册走的是代理出口，协议/NSFW 必须走同一条出口，
        # 否则直连（或换出口）会超时/被风控 → 「最后一步 NSFW 失败」。
        self.proxies: Dict[str, str] = dict(proxies or {})

    # ------------------------------------------------------------------ #
    # 内部：统一的 RPC 调用
    # ------------------------------------------------------------------ #
    def _call(
        self,
        *,
        url: str,
        fields: bytes,
        origin: str,
        referer: str,
        cookies: Dict[str, str],
        impersonate: str,
        user_agent: Optional[str],
        timeout: int,
        grpc_web: bool = True,
        proxies: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        headers = {
            "content-type": "application/grpc-web+proto",
            "origin": origin,
            "referer": referer,
            "user-agent": user_agent or DEFAULT_USER_AGENT,
            "x-user-agent": "connect-es/2.1.1",
            "accept": "*/*",
        }
        if grpc_web:
            headers["x-grpc-web"] = "1"
        try:
            resp = requests.post(
                url,
                headers=headers,
                cookies={k: v for k, v in cookies.items() if v},
                data=grpc_frame(fields),
                impersonate=impersonate or "chrome120",
                timeout=timeout,
                proxies=proxies if proxies is not None else self.proxies,
            )
        except Exception as e:
            return {
                "ok": False,
                "status_code": None,
                "grpc_status": None,
                "grpc_message": "",
                "error": f"网络异常: {e}",
                "body": b"",
            }

        body = resp.content or b""
        grpc_status = resp.headers.get("grpc-status")
        grpc_message = resp.headers.get("grpc-message") or ""
        if not grpc_message and body[:1] not in (b"\x00", b"\x01"):
            # 少数实现把错误文本放 body
            try:
                txt = body.decode("utf-8", "replace").strip()
                if txt.startswith("{"):
                    grpc_message = str(json.loads(txt).get("error") or "")[:200]
            except Exception:
                pass

        ok = _status_ok(resp.status_code, grpc_status)
        error = None
        if resp.status_code == 403:
            error = "403 Forbidden（Cloudflare 拦截，缺少 cf_clearance 或出口被风控）"
        elif resp.status_code == 429:
            error = "429 限流"
        elif resp.status_code != 200:
            error = f"HTTP {resp.status_code}"
        elif not ok:
            msg = grpc_message.replace("%20", " ").strip()
            error = f"gRPC {grpc_status}" + (f": {msg}" if msg else "")

        return {
            "ok": ok,
            "status_code": resp.status_code,
            "grpc_status": grpc_status,
            "grpc_message": grpc_message,
            "error": error,
            "body": body,
        }

    def _cookies(self, sso: str, sso_rw: str, cf_clearance: Optional[str]) -> Dict[str, str]:
        clearance = (cf_clearance if cf_clearance is not None else self.cf_clearance).strip()
        return {"sso": sso, "sso-rw": sso_rw or sso, "cf_clearance": clearance}

    # ------------------------------------------------------------------ #
    # 预热 grok.com 会话：拿站点下发的附加 cookie，并判断 sso 是否被认
    # ------------------------------------------------------------------ #
    def warm_session(
        self,
        sso: str,
        sso_rw: str = "",
        impersonate: str = "chrome120",
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
        timeout: int = 20,
        proxies: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        先 GET 一次 grok.com（带 sso），让服务端补齐会话 cookie。

        返回 {ok, cookies, redirected_to_signin, status_code, error}
        ok=False 仅表示预热本身失败（不影响后续尝试）。
        """
        base = self._cookies(sso, sso_rw, cf_clearance)
        jar: Dict[str, str] = {k: v for k, v in base.items() if v}
        try:
            resp = requests.get(
                f"{GROK_AUTH_BASE}/",
                headers={
                    "user-agent": user_agent or DEFAULT_USER_AGENT,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                cookies=jar,
                impersonate=impersonate or "chrome120",
                allow_redirects=True,
                timeout=timeout,
                proxies=proxies if proxies is not None else self.proxies,
            )
        except Exception as e:
            return {"ok": False, "cookies": jar, "redirected_to_signin": False,
                    "status_code": None, "error": f"预热异常: {e}"}

        try:
            for c in resp.cookies.jar:
                if c.name and c.value:
                    jar[c.name] = c.value
        except Exception:
            pass

        final_url = str(getattr(resp, "url", "") or "")
        signin = "/sign-in" in final_url or "/sign-up" in final_url
        return {
            "ok": resp.status_code == 200 and not signin,
            "cookies": jar,
            "redirected_to_signin": signin,
            "status_code": resp.status_code,
            "error": None if not signin else "sso 在 grok.com 未登录态（被重定向登录页）",
        }

    # ------------------------------------------------------------------ #
    # 读回当前 FeatureControls（用于校验 / 诊断）
    # ------------------------------------------------------------------ #
    def get_feature_controls(
        self,
        sso: str,
        sso_rw: str = "",
        impersonate: str = "chrome120",
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        res = self._call(
            url=f"{GROK_AUTH_BASE}/auth_mgmt.AuthManagement/GetUserFeatureControls",
            fields=b"",
            origin=GROK_AUTH_BASE,
            referer=f"{GROK_AUTH_BASE}/",
            cookies=self._cookies(sso, sso_rw, cf_clearance),
            impersonate=impersonate,
            user_agent=user_agent,
            timeout=timeout,
        )
        msg = _decode_grpc_message(res.get("body") or b"")
        res["message"] = msg
        res["hex_reply"] = (res.get("body") or b"").hex()
        return res

    # ------------------------------------------------------------------ #
    # 开启 NSFW
    # ------------------------------------------------------------------ #
    def enable_nsfw(
        self,
        sso: str,
        sso_rw: str,
        impersonate: str,
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
        timeout: int = 15,
        retries: int = 2,
    ) -> Dict[str, Any]:
        """
        启用 always_show_nsfw_content。

        返回: {
            ok: bool,             # 服务端真正接受（grpc-status 0）
            verified: bool|None,  # 读回校验结果；None=无法判定
            hex_reply: str,
            status_code: int | None,
            grpc_status: str | None,
            grpc_message: str,
            error: str | None,
        }

        说明：
        - 这些 RPC 失败时同样返回 HTTP 200，只有 grpc-status 非 0 才代表失败；
          旧代码用「body 非空」判定成功，会把空响应的成功误判成失败。
        - 成功后读回 GetUserFeatureControls 做校验，避免「请求对了但设置没生效」。
        """
        empty = {
            "ok": False,
            "verified": None,
            "hex_reply": "",
            "status_code": None,
            "grpc_status": None,
            "grpc_message": "",
        }
        if not sso:
            return {**empty, "error": "缺少 sso"}
        if not sso_rw:
            return {**empty, "error": "缺少 sso-rw"}

        # field1 = { field2: true }        -> 打开开关
        # field2 = { field1: "always_show_nsfw_content" }
        fields = (
            pb_len_field(1, pb_varint_field(2, 1))
            + pb_len_field(2, pb_len_field(1, NSFW_FLAG.encode()))
        )

        url = f"{GROK_AUTH_BASE}/auth_mgmt.AuthManagement/UpdateUserFeatureControls"

        # 先预热：让 grok.com 补发会话 cookie；顺便判断这个 sso 在 grok.com 是否登录态
        warm = self.warm_session(
            sso=sso,
            sso_rw=sso_rw,
            impersonate=impersonate,
            user_agent=user_agent,
            cf_clearance=cf_clearance,
            timeout=timeout,
        )
        cookies = dict(warm.get("cookies") or self._cookies(sso, sso_rw, cf_clearance))
        signin_redirect = bool(warm.get("redirected_to_signin"))

        last: Dict[str, Any] = {**empty, "error": "未执行"}
        attempts = max(1, int(retries) + 1)
        for i in range(attempts):
            res = self._call(
                url=url,
                fields=fields,
                origin=GROK_AUTH_BASE,
                referer=f"{GROK_AUTH_BASE}/?_s=data",
                cookies=cookies,
                impersonate=impersonate,
                user_agent=user_agent,
                timeout=timeout,
            )
            body = res.pop("body", b"")
            last = {
                "ok": bool(res.get("ok")),
                "verified": None,
                "hex_reply": body.hex(),
                "status_code": res.get("status_code"),
                "grpc_status": res.get("grpc_status"),
                "grpc_message": res.get("grpc_message") or "",
                "error": res.get("error"),
                "signin_redirect": signin_redirect,
            }
            if last["ok"]:
                break
            # 403/429 之外的重试意义有限，但仍给一次机会（出口抖动）
            if i + 1 < attempts:
                time.sleep(0.6 * (i + 1))

        if last["ok"]:
            read = self.get_feature_controls(
                sso=sso,
                sso_rw=sso_rw,
                impersonate=impersonate,
                user_agent=user_agent,
                cf_clearance=cf_clearance,
                timeout=timeout,
            )
            last["readback_hex"] = read.get("hex_reply") or ""
            last["readback_ok"] = bool(read.get("ok"))
            # 读回成功只说明「设置接口可读」；字段号未知，不做脆弱解析，
            # 因此 verified 保持 None —— 不再制造第二个「假绿」。
            if read.get("ok"):
                last["readback_len"] = len(read.get("message") or b"")
        elif signin_redirect and not last.get("error"):
            last["error"] = "sso 在 grok.com 不是登录态（预热被重定向到登录页）"
        return last

    # ------------------------------------------------------------------ #
    # 兼容旧接口：Unhinged / 二次验证
    # ------------------------------------------------------------------ #
    def enable_unhinged(
        self,
        sso: str,
        sso_rw: str = "",
        impersonate: str = "chrome120",
        user_agent: Optional[str] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        旧实现把 sso 当 sso-rw 用、且只看 HTTP 200 就报成功——而这些 RPC
        失败也回 200，所以它「永远成功」，把 NSFW 状态刷成假绿。

        现在：使用真实 sso-rw，并且只认 grpc-status 0。
        """
        res = self._call(
            url=f"{GROK_AUTH_BASE}/auth_mgmt.AuthManagement/UpdateUserFeatureControls",
            fields=pb_varint_field(1, 1) + pb_varint_field(2, 1),
            origin=GROK_AUTH_BASE,
            referer=f"{GROK_AUTH_BASE}/",
            cookies=self._cookies(sso, sso_rw, None),
            impersonate=impersonate,
            user_agent=user_agent,
            timeout=timeout,
        )
        res.pop("body", None)
        return {
            "ok": bool(res.get("ok")),
            "status_code": res.get("status_code"),
            "grpc_status": res.get("grpc_status"),
            "grpc_message": res.get("grpc_message") or "",
            "error": res.get("error"),
        }
