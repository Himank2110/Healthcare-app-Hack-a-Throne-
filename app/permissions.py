from fastapi import HTTPException, status

from app.auth import CurrentUser


def require_role(user: CurrentUser, *allowed_roles: str) -> None:
    if user.role not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
