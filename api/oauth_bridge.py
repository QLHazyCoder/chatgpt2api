from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from api.support import require_admin
from services.oauth_bridge_service import oauth_bridge_service


class OAuthExchangeRequest(BaseModel):
    session_id: str
    code: str
    state: str


def _require_admin_with_header(authorization: str | None, admin_key: str | None):
    if str(admin_key or "").strip():
        return require_admin(f"Bearer {str(admin_key).strip()}")
    return require_admin(authorization)


def create_router() -> APIRouter:
    router = APIRouter()

    @router.post("/api/admin/oauth/generate-auth-url")
    async def generate_auth_url(
        authorization: str | None = Header(default=None),
        x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
    ):
        _require_admin_with_header(authorization, x_admin_key)
        return oauth_bridge_service.create_auth_session()

    @router.post("/api/admin/oauth/exchange-code")
    async def exchange_code(
        body: OAuthExchangeRequest,
        authorization: str | None = Header(default=None),
        x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
    ):
        _require_admin_with_header(authorization, x_admin_key)
        try:
            return oauth_bridge_service.exchange_code(
                session_id=body.session_id,
                code=body.code,
                state=body.state,
            )
        except RuntimeError as exc:
            message = str(exc)
            status_code = 400 if any(keyword in message.lower() for keyword in ("required", "missing", "expired", "state")) else 502
            raise HTTPException(status_code=status_code, detail={"error": message}) from exc

    return router
