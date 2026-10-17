import hashlib
import base64
from io import BytesIO
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload
import qrcode

from app.auth import CurrentUser, get_current_user
from app.database import get_db
from app.models import AccessAudit, Encounter, Patient, Prescription, PrescriptionShare
from app.permissions import require_role
from app.schemas import (
    PrescriptionRead,
    PrescriptionShareCreate,
    PrescriptionShareRedeem,
    PrescriptionShareRevokeRead,
)

router = APIRouter(prefix="/prescriptions", tags=["prescription sharing"])
redeem_router = APIRouter(prefix="/prescription-shares", tags=["prescription sharing"])
SHARE_LIFETIME = timedelta(minutes=5)


@router.post(
    "/{prescription_id}/share",
    response_model=PrescriptionShareCreate,
    status_code=status.HTTP_201_CREATED,
)
def create_prescription_share(
    prescription_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PrescriptionShareCreate:
    require_role(user, "patient")
    statement = (
        select(Prescription)
        .join(Encounter)
        .join(Patient)
        .where(Prescription.id == prescription_id, Patient.user_id == user.id)
        .options(selectinload(Prescription.items))
    )
    prescription = db.scalar(statement)
    if prescription is None:
        raise HTTPException(status_code=404, detail="Prescription not found")
    if prescription.status != "active":
        raise HTTPException(status_code=409, detail="Only active prescriptions can be shared")

    raw_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + SHARE_LIFETIME
    share = PrescriptionShare(
        prescription_id=prescription.id,
        token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
        created_by_user_id=user.id,
        expires_at=expires_at,
    )
    db.add(share)
    db.add(AccessAudit(user_id=user.id, prescription_id=prescription.id, action="share_created"))
    db.commit()
    qr_image = qrcode.make(raw_token)
    qr_buffer = BytesIO()
    qr_image.save(qr_buffer, format="PNG")
    qr_code_data_uri = "data:image/png;base64," + base64.b64encode(qr_buffer.getvalue()).decode("ascii")
    return PrescriptionShareCreate(
        share_id=share.id,
        share_token=raw_token,
        qr_payload=raw_token,
        qr_code_data_uri=qr_code_data_uri,
        expires_at=expires_at,
    )


@redeem_router.post("/{share_id}/revoke", response_model=PrescriptionShareRevokeRead)
def revoke_prescription_share(
    share_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PrescriptionShareRevokeRead:
    require_role(user, "patient")
    share = db.scalar(
        select(PrescriptionShare).where(
            PrescriptionShare.id == share_id,
            PrescriptionShare.created_by_user_id == user.id,
        )
    )
    if share is None:
        raise HTTPException(status_code=404, detail="Share not found")
    if share.redeemed_at is not None or share.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Share has already been redeemed or revoked")

    now = datetime.now(timezone.utc)
    expires_at = share.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(status_code=409, detail="Share has expired")

    result = db.execute(
        update(PrescriptionShare)
        .where(
            PrescriptionShare.id == share.id,
            PrescriptionShare.created_by_user_id == user.id,
            PrescriptionShare.redeemed_at.is_(None),
            PrescriptionShare.revoked_at.is_(None),
            PrescriptionShare.expires_at > now,
        )
        .values(revoked_at=now)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Share is no longer available to revoke")

    db.add(
        AccessAudit(
            user_id=user.id,
            prescription_id=share.prescription_id,
            action="share_revoked",
        )
    )
    db.commit()
    return PrescriptionShareRevokeRead(share_id=share.id)


@redeem_router.post("/redeem", response_model=PrescriptionRead)
def redeem_prescription_share(
    body: PrescriptionShareRedeem,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Prescription:
    require_role(user, "pharmacist")
    token_hash = hashlib.sha256(body.share_token.encode("utf-8")).hexdigest()
    share = db.scalar(select(PrescriptionShare).where(PrescriptionShare.token_hash == token_hash))
    if share is None or share.redeemed_at is not None or share.revoked_at is not None:
        raise HTTPException(status_code=410, detail="Share code is invalid, expired, or already used")

    now = datetime.now(timezone.utc)
    expires_at = share.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(status_code=410, detail="Share code is invalid, expired, or already used")

    result = db.execute(
        update(PrescriptionShare)
        .where(
            PrescriptionShare.id == share.id,
            PrescriptionShare.redeemed_at.is_(None),
            PrescriptionShare.revoked_at.is_(None),
            PrescriptionShare.expires_at > now,
        )
        .values(redeemed_at=now, redeemed_by_user_id=user.id)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=410, detail="Share code is invalid, expired, or already used")

    prescription = db.scalar(
        select(Prescription)
        .where(Prescription.id == share.prescription_id)
        .options(selectinload(Prescription.items))
    )
    if prescription is None:
        db.rollback()
        raise HTTPException(status_code=410, detail="Share code is invalid, expired, or already used")
    if prescription.status != "active":
        db.rollback()
        raise HTTPException(status_code=410, detail="Share code is invalid, expired, or already used")
    db.add(AccessAudit(user_id=user.id, prescription_id=prescription.id, action="share_redeemed"))
    db.commit()
    return prescription
