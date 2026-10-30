"""
注册机配件
"""
from .email_service import EmailService
from .turnstile_service import TurnstileService
from .user_agreement_service import UserAgreementService
from .nsfw_service import NsfwSettingsService

# Castle / same-session（CLEAN 主路径）
from .castle_service import (  # noqa: F401
    MIN_CASTLE_LEN,
    SITE as CASTLE_SITE,
    is_castle_token_usable,
    mint_js_args,
    mint_signup_signals,
    new_conversion_id,
    castle_mint_enabled,
    last_error as castle_last_error,
)
from .same_session_register import same_session_register, parse_proxy_spec

try:
    from .antibot_service import AntibotService
except Exception:  # pragma: no cover
    AntibotService = None  # type: ignore


class CastleService:
    """
    兼容旧调用：mint() 走浏览器 fiber。
    注意：拆会话 mint 再 curl 注册会被 BOT_FLAG_SOURCE_CASTLE deny。
    CLEAN 路径请用 same_session_register（同页 mint + 页内 fetch）。
    """

    def __init__(self):
        import os

        self.mode = (os.getenv("CASTLE_MODE") or "skip").strip().lower()
        self.min_len = MIN_CASTLE_LEN
        self.timeout_s = int(os.getenv("CASTLE_TIMEOUT_S") or "120")
        self.last_error = ""
        self.last_token = ""
        self.last_meta: dict = {}
        self.last_cookies: dict = {}
        self.last_user_agent = ""

    def mint(self, stop_event=None, proxy=None, user_agent=None):
        self.last_error = ""
        self.last_token = ""
        self.last_meta = {}
        self.last_cookies = {}
        self.last_user_agent = ""
        if self.mode in ("skip", "none", "off", "0", "false"):
            self.last_error = "CASTLE_MODE=skip"
            return None
        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            self.last_error = "stopped"
            return None
        try:
            from .castle_service import mint_castle_from_browser

            r = mint_castle_from_browser(proxy=proxy, user_agent=user_agent)
            self.last_meta = r if isinstance(r, dict) else {"raw": r}
            if isinstance(r, dict):
                self.last_cookies = dict(r.get("cookies") or {})
                self.last_user_agent = str(r.get("user_agent") or "")
            tok = (r or {}).get("castle") if isinstance(r, dict) else None
            if tok and is_castle_token_usable(tok):
                self.last_token = tok
                return tok
            self.last_error = (r or {}).get("error") or castle_last_error() or "mint fail"
            return None
        except Exception as e:
            self.last_error = str(e)
            return None


__all__ = [
    "EmailService",
    "TurnstileService",
    "UserAgreementService",
    "NsfwSettingsService",
    "CastleService",
    "AntibotService",
    "same_session_register",
    "parse_proxy_spec",
    "mint_signup_signals",
    "new_conversion_id",
    "castle_mint_enabled",
    "is_castle_token_usable",
    "MIN_CASTLE_LEN",
]
