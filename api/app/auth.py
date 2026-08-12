"""No auth logic lives here on purpose. Identity is owned entirely by
better-auth in sanitaizer-web (Postgres tables `user`/`session`, same `jobs`
database this service already uses). This API is only ever called by
sanitaizer-web's own server-side route handlers (src/app/api/*), which
validate the better-auth session first and then forward the caller's
user id/role through trusted headers, guarded by a shared secret this
service never exposes to the browser.
"""
import os

from fastapi import Header, HTTPException

INTERNAL_SECRET = os.environ.get("JOBS_INTERNAL_SECRET", "dev-only-shared-secret-change-me")


def require_internal_caller(
    x_internal_secret: str = Header(...),
    x_user_id: str = Header(...),
    x_user_role: str = Header(default="user"),
):
    if x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(401, "invalid internal secret")
    return {"id": x_user_id, "role": x_user_role}


def require_admin_caller(
    x_internal_secret: str = Header(...),
    x_user_id: str = Header(...),
    x_user_role: str = Header(default="user"),
):
    if x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(401, "invalid internal secret")
    if x_user_role != "admin":
        raise HTTPException(403, "admin only")
    return {"id": x_user_id, "role": x_user_role}
