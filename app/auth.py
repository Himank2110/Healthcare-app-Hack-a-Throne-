import hashlib
import hmac
import logging
import secrets
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import PasswordResetToken, Patient, User
from app.schemas import (
    AccountRead,
    AccountCredentials,
    AccountRegistration,
    DevTokenRequest,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetResponse,
    RegistrationRead,
    StaffAccountCreate,
    TokenRead,
)
from app.throttling import auth_throttle

bearer_scheme = HTTPBearer(auto_error=False)
router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger(__name__)
PASSWORD_RESET_LIFETIME = timedelta(minutes=20)
LOGIN_WINDOW_SECONDS = 15 * 60
RESET_WINDOW_SECONDS = 60 * 60


@dataclass(frozen=True)
class CurrentUser:
    id: int
    role: str


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=5, dklen=32
    )
    return "$".join(
        (
            "scrypt",
            "16384",
            "8",
            "5",
            salt.hex(),
            password_hash.hex(),
        )
    )


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, n, r, p, salt_hex, expected_hex = encoded.split("$")
        if algorithm != "scrypt" or int(n) != 2**14 or int(r) != 8 or int(p) not in {1, 5}:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def password_needs_rehash(encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        algorithm, n, r, p, _salt_hex, _hash_hex = encoded.split("$")
        return algorithm != "scrypt" or (int(n), int(r), int(p)) != (2**14, 8, 5)
    except (ValueError, TypeError):
        return False


def issue_token(user: User) -> TokenRead:
    expires = datetime.now(timezone.utc) + timedelta(minutes=30)
    token = jwt.encode(
        {"sub": str(user.id), "role": user.role, "ver": user.token_version, "exp": expires},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    return TokenRead(access_token=token, user_id=user.id, role=user.role)


def account_identifier_is_taken(db: Session, email: str, username: str) -> bool:
    return db.scalar(
        select(User.id).where(or_(User.email == email, User.username == username))
    ) is not None


def account_read(account: User) -> AccountRead:
    return AccountRead(
        id=account.id,
        username=account.username,
        email=account.email,
        display_name=account.display_name,
        role=account.role,
        status=account.status,
        requested_role=account.requested_role,
        organization_type=account.organization_type,
        organization_name=account.organization_name,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> CurrentUser:
    try:
        if credentials is None:
            raise ValueError("Missing bearer token")
        token = credentials.credentials
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        user_id = int(payload["sub"])
        role = str(payload["role"])
        if role not in {"patient", "clinician", "pharmacist", "admin"}:
            raise ValueError("Unknown role")
        user = db.get(User, user_id)
        if (
            user is None
            or user.role != role
            or user.status != "active"
            or int(payload.get("ver", 0)) != user.token_version
        ):
            raise ValueError("Unknown or changed user")
    except (JWTError, KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(id=user_id, role=role)


@router.post("/register", response_model=RegistrationRead, status_code=status.HTTP_201_CREATED)
def register_account(body: AccountRegistration, db: Session = Depends(get_db)) -> RegistrationRead:
    if account_identifier_is_taken(db, body.email, body.username):
        raise HTTPException(status_code=409, detail="That email or username is already in use")
    is_patient = body.role == "patient"
    user = User(
        role="patient" if is_patient else "pending",
        display_name=body.display_name,
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        status="active" if is_patient else "pending",
        requested_role=None if is_patient else body.role,
        organization_type=body.organization_type,
        organization_name=body.organization_name,
    )
    db.add(user)
    try:
        db.flush()
        if is_patient:
            db.add(Patient(display_name=body.display_name, user_id=user.id))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="That email or username is already in use")
    db.refresh(user)
    if is_patient:
        token = issue_token(user).access_token
        return RegistrationRead(
            **account_read(user).model_dump(),
            access_token=token,
            message="Patient account created.",
        )
    return RegistrationRead(
        **account_read(user).model_dump(),
        access_token=None,
        message="Registration received. A system administrator must approve this professional account before sign-in.",
    )


def throttle_key(namespace: str, value: str) -> str:
    return auth_throttle.key(namespace, value)


def enforce_throttle(keys: list[tuple[str, int, int]]) -> None:
    retries = [auth_throttle.retry_after(key, limit, window) for key, limit, window in keys]
    retry_after = max(retries, default=0)
    if retry_after:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Wait before trying again.",
            headers={"Retry-After": str(retry_after)},
        )


@router.post("/login", response_model=TokenRead)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenRead:
    ip = request.client.host if request.client else "unknown"
    account_key = throttle_key("login-account", body.identifier)
    ip_key = throttle_key("login-ip", ip)
    throttle_keys = [
        (account_key, 5, LOGIN_WINDOW_SECONDS),
        (ip_key, 30, LOGIN_WINDOW_SECONDS),
    ]
    enforce_throttle(throttle_keys)
    user = db.scalar(
        select(User).where(or_(User.email == body.identifier, User.username == body.identifier))
    )
    if user is None or not verify_password(body.password, user.password_hash):
        auth_throttle.record(account_key, LOGIN_WINDOW_SECONDS)
        auth_throttle.record(ip_key, LOGIN_WINDOW_SECONDS)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.status == "pending":
        raise HTTPException(status_code=403, detail="This account is awaiting administrator approval")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="This account is not active")
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
        db.commit()
    auth_throttle.clear(account_key)
    return issue_token(user)


def send_password_reset_email(email: str, raw_token: str) -> None:
    message = EmailMessage()
    message["Subject"] = "Reset your Healthcare Records account password"
    message["From"] = settings.smtp_from
    message["To"] = email
    message.set_content(
        "A password reset was requested for your account.\n\n"
        f"Your one-time reset token is: {raw_token}\n\n"
        "Enter it in POST /api/v1/auth/password-reset/confirm with your new password. "
        "The token expires in 20 minutes. If you did not request this, ignore this email."
    )
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
        if settings.smtp_starttls:
            client.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password)
        client.send_message(message)


@router.post(
    "/password-reset/request",
    response_model=PasswordResetResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_password_reset(
    body: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> PasswordResetResponse:
    ip = request.client.host if request.client else "unknown"
    email_key = throttle_key("reset-email", body.email)
    ip_key = throttle_key("reset-ip", ip)
    throttle_keys = [(email_key, 3, RESET_WINDOW_SECONDS), (ip_key, 10, RESET_WINDOW_SECONDS)]
    enforce_throttle(throttle_keys)
    for key, _limit, window in throttle_keys:
        auth_throttle.record(key, window)

    raw_token = secrets.token_urlsafe(32)
    user = db.scalar(select(User).where(User.email == body.email))
    if user is not None:
        now = datetime.now(timezone.utc)
        db.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
                expires_at=now + PASSWORD_RESET_LIFETIME,
            )
        )
        db.commit()
        if settings.app_env.strip().lower() == "development":
            dev_token = raw_token
        else:
            dev_token = None
            try:
                send_password_reset_email(body.email, raw_token)
            except (OSError, smtplib.SMTPException):
                logger.warning("Password reset email delivery failed")
    else:
        # A random development token keeps the response shape identical for unknown addresses.
        dev_token = raw_token if settings.app_env.strip().lower() == "development" else None
    return PasswordResetResponse(
        message="If an account exists for that email, password reset instructions will be sent.",
        dev_reset_token=dev_token,
    )


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
def confirm_password_reset(
    body: PasswordResetConfirm,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    ip = request.client.host if request.client else "unknown"
    ip_key = throttle_key("reset-confirm-ip", ip)
    enforce_throttle([(ip_key, 20, RESET_WINDOW_SECONDS)])
    auth_throttle.record(ip_key, RESET_WINDOW_SECONDS)

    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    reset_token = db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    expires_at = reset_token.expires_at if reset_token is not None else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if (
        reset_token is None
        or reset_token.used_at is not None
        or expires_at is None
        or expires_at <= now
    ):
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired")

    user = db.get(User, reset_token.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="Reset token is invalid or expired")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    db.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
        .values(used_at=now)
    )
    db.commit()
    auth_throttle.clear(throttle_key("login-account", user.email or user.username or ""))
    return {"message": "Password reset. Sign in with your new password."}


@router.get("/me", response_model=AccountRead)
def get_my_account(
    db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
) -> AccountRead:
    account = db.get(User, user.id)
    if account is None:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    return account_read(account)


@router.post("/bootstrap-admin", response_model=AccountRead, status_code=status.HTTP_201_CREATED)
def bootstrap_admin(
    body: AccountCredentials,
    bootstrap_key: str | None = Header(default=None, alias="X-Bootstrap-Key"),
    db: Session = Depends(get_db),
) -> AccountRead:
    configured_key = settings.bootstrap_admin_key
    if (
        not configured_key
        or bootstrap_key is None
        or not hmac.compare_digest(bootstrap_key, configured_key)
    ):
        raise HTTPException(status_code=404, detail="Not found")
    existing_admin = db.scalar(
        select(User.id).where(User.role == "admin", User.email.is_not(None))
    )
    if existing_admin is not None:
        raise HTTPException(status_code=409, detail="An admin account has already been created")
    account = User(
        role="admin",
        display_name=body.display_name,
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        status="active",
    )
    db.add(account)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="That email or username is already in use")
    db.refresh(account)
    return account_read(account)


@router.get("/pending-accounts", response_model=list[AccountRead])
def list_pending_accounts(
    db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)
) -> list[AccountRead]:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    pending = db.scalars(
        select(User).where(User.status == "pending").order_by(User.id)
    ).all()
    return [account_read(account) for account in pending]


@router.post("/accounts/{account_id}/approve", response_model=AccountRead)
def approve_account(
    account_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AccountRead:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    account = db.get(User, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    if account.status != "pending" or account.requested_role not in {"clinician", "pharmacist"}:
        raise HTTPException(status_code=409, detail="Account is not awaiting professional approval")
    account.role = account.requested_role
    account.requested_role = None
    account.status = "active"
    db.commit()
    db.refresh(account)
    return account_read(account)


@router.post("/accounts/{account_id}/reject", response_model=AccountRead)
def reject_account(
    account_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AccountRead:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    account = db.get(User, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    if account.status != "pending":
        raise HTTPException(status_code=409, detail="Account is not awaiting approval")
    account.status = "rejected"
    db.commit()
    db.refresh(account)
    return account_read(account)


@router.post("/users", response_model=AccountRead, status_code=status.HTTP_201_CREATED)
def provision_staff_account(
    body: StaffAccountCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AccountRead:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    if account_identifier_is_taken(db, body.email, body.username):
        raise HTTPException(status_code=409, detail="That email or username is already in use")
    account = User(
        role=body.role,
        display_name=body.display_name,
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        status="active",
        organization_type=body.organization_type,
        organization_name=body.organization_name,
    )
    db.add(account)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="That email or username is already in use")
    db.refresh(account)
    return account_read(account)


@router.post("/dev-token", response_model=TokenRead)
def create_development_token(
    body: DevTokenRequest, db: Session = Depends(get_db)
) -> TokenRead:
    if settings.app_env.lower() != "development" or not settings.enable_dev_auth:
        raise HTTPException(status_code=404, detail="Not found")
    if body.role not in {"patient", "clinician", "pharmacist", "admin"}:
        raise HTTPException(status_code=422, detail="Unsupported role")

    user = db.scalar(
        select(User).where(User.role == body.role, User.display_name == body.display_name)
    )
    if user is None:
        user = User(role=body.role, display_name=body.display_name)
        db.add(user)
        db.commit()
        db.refresh(user)

    if body.role == "patient" and db.scalar(select(Patient).where(Patient.user_id == user.id)) is None:
        db.add(Patient(display_name=user.display_name or "Demo patient", user_id=user.id))
        db.commit()

    return issue_token(user)
