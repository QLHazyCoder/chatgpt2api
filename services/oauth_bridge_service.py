from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

from curl_cffi.requests import Session

from services.account_service import account_service
from services.config import DATA_DIR


AUTH_BASE = "https://auth.openai.com"
PLATFORM_BASE = "https://platform.openai.com"
TOKEN_ENDPOINT = f"{AUTH_BASE}/oauth/token"
PLATFORM_OAUTH_CLIENT_ID = "app_2SKx67EdpoN0G6j64rFvigXD"
PLATFORM_OAUTH_REDIRECT_URI = f"{PLATFORM_BASE}/auth/callback"
PLATFORM_OAUTH_AUDIENCE = "https://api.openai.com/v1"
PLATFORM_AUTH0_CLIENT = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
REQUESTED_SCOPE = "openid profile email offline_access"
SESSION_TTL_SECONDS = 1800
SESSION_FILE = DATA_DIR / "oauth_bridge_sessions.json"


def _now() -> int:
    return int(time.time())


def _generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload = str(token or "").split(".")[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        data = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


class OAuthBridgeService:
    def __init__(self, store_file: Path):
        self._store_file = store_file
        self._lock = threading.RLock()
        self._sessions = self._load()

    def _load(self) -> dict[str, dict]:
        try:
            data = json.loads(self._store_file.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self) -> None:
        self._store_file.parent.mkdir(parents=True, exist_ok=True)
        self._store_file.write_text(json.dumps(self._sessions, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _cleanup_expired(self) -> None:
        now = _now()
        expired = [
            session_id
            for session_id, payload in self._sessions.items()
            if now - int(payload.get("created_at") or 0) > SESSION_TTL_SECONDS
        ]
        for session_id in expired:
            self._sessions.pop(session_id, None)
        if expired:
            self._save()

    def _build_auth_url(self, state: str, code_challenge: str) -> str:
        params = {
            "issuer": AUTH_BASE,
            "client_id": PLATFORM_OAUTH_CLIENT_ID,
            "audience": PLATFORM_OAUTH_AUDIENCE,
            "redirect_uri": PLATFORM_OAUTH_REDIRECT_URI,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "scope": REQUESTED_SCOPE,
            "response_type": "code",
            "response_mode": "query",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": secrets.token_urlsafe(32),
            "auth0Client": PLATFORM_AUTH0_CLIENT,
            "device_id": str(uuid.uuid4()),
        }
        return f"{AUTH_BASE}/api/accounts/authorize?{urlencode(params)}"

    def create_auth_session(self) -> dict[str, str]:
        with self._lock:
            self._cleanup_expired()
            session_id = secrets.token_urlsafe(24)
            state = secrets.token_urlsafe(32)
            code_verifier, code_challenge = _generate_pkce()
            auth_url = self._build_auth_url(state, code_challenge)
            self._sessions[session_id] = {
                "state": state,
                "code_verifier": code_verifier,
                "created_at": _now(),
                "redirect_uri": PLATFORM_OAUTH_REDIRECT_URI,
            }
            self._save()
            return {
                "session_id": session_id,
                "state": state,
                "auth_url": auth_url,
            }

    @staticmethod
    def _exchange_code(code: str, code_verifier: str) -> dict:
        session = Session(impersonate="chrome")
        try:
            response = session.post(
                TOKEN_ENDPOINT,
                data={
                    "grant_type": "authorization_code",
                    "client_id": PLATFORM_OAUTH_CLIENT_ID,
                    "redirect_uri": PLATFORM_OAUTH_REDIRECT_URI,
                    "code": code,
                    "code_verifier": code_verifier,
                },
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=30,
            )
            try:
                payload = response.json()
            except Exception:
                payload = {}
            if response.status_code != 200:
                detail = ""
                if isinstance(payload, dict):
                    detail = str(payload.get("error_description") or payload.get("error") or payload.get("message") or "").strip()
                if not detail:
                    detail = response.text[:300]
                raise RuntimeError(detail or f"oauth_token_http_{response.status_code}")
            if not isinstance(payload, dict):
                raise RuntimeError("oauth token response is invalid")
            return payload
        finally:
            session.close()

    def exchange_code(self, session_id: str, code: str, state: str) -> dict:
        session_id = str(session_id or "").strip()
        code = str(code or "").strip()
        state = str(state or "").strip()
        if not session_id:
            raise RuntimeError("session_id is required")
        if not code:
            raise RuntimeError("code is required")
        if not state:
            raise RuntimeError("state is required")

        with self._lock:
            self._cleanup_expired()
            session_payload = dict(self._sessions.get(session_id) or {})
        if not session_payload:
            raise RuntimeError("oauth session is missing or expired")

        expected_state = str(session_payload.get("state") or "").strip()
        if expected_state and expected_state != state:
            raise RuntimeError("oauth callback state does not match the current session")

        token_payload = self._exchange_code(code, str(session_payload.get("code_verifier") or "").strip())
        access_token = str(token_payload.get("access_token") or "").strip()
        refresh_token = str(token_payload.get("refresh_token") or "").strip()
        id_token = str(token_payload.get("id_token") or "").strip()
        if not access_token:
            raise RuntimeError("oauth token response did not return access_token")

        claims = _decode_jwt_payload(id_token) or _decode_jwt_payload(access_token)
        email = str(claims.get("email") or "").strip()

        account_service.add_accounts([access_token])
        account_service.update_account(access_token, {
            "refresh_token": refresh_token or None,
            "id_token": id_token or None,
            "email": email or None,
            "oauth_client_id": PLATFORM_OAUTH_CLIENT_ID,
        })
        refresh_result = account_service.refresh_accounts([access_token])
        account = account_service.get_account(access_token)
        errors = refresh_result.get("errors") if isinstance(refresh_result, dict) else []
        if account is None and errors:
            raise RuntimeError(str((errors[0] or {}).get("error") or "failed to import oauth account"))

        with self._lock:
            self._sessions.pop(session_id, None)
            self._save()

        account = account or account_service.get_account(access_token) or {}
        resolved_email = str(account.get("email") or email or "").strip()
        return {
            "message": f"OAuth 账号 {resolved_email or 'unknown'} 添加成功",
            "email": resolved_email or None,
            "plan_type": str(account.get("type") or "").strip() or None,
            "status": str(account.get("status") or "").strip() or None,
        }


oauth_bridge_service = OAuthBridgeService(SESSION_FILE)
