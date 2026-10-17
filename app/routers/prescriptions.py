from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from app.auth import CurrentUser, get_current_user
from app.database import get_db
from app.models import AccessAudit, Encounter, Patient, Prescription, PrescriptionItem, PrescriptionShare, User
from app.permissions import require_role
from app.schemas import (
    PrescriptionAuditRead,
    PrescriptionCreate,
    PrescriptionRead,
    PrescriptionStatusUpdate,
)

router = APIRouter(prefix="/prescriptions", tags=["prescriptions"])


@router.post("", response_model=PrescriptionRead, status_code=status.HTTP_201_CREATED)
def create_prescription(
    body: PrescriptionCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Prescription:
    require_role(user, "clinician", "admin")
    encounter = db.get(Encounter, body.encounter_id)
    if encounter is None:
        raise HTTPException(status_code=404, detail="Encounter not found")
    if user.role == "clinician" and encounter.clinician_id != user.id:
        raise HTTPException(status_code=403, detail="You can only prescribe for your own encounters")

    prescription = Prescription(
        encounter=encounter,
        items=[PrescriptionItem(**item.model_dump()) for item in body.items],
    )
    db.add(prescription)
    db.commit()
    db.refresh(prescription)
    return prescription


@router.get("/mine", response_model=list[PrescriptionRead])
def list_my_prescriptions(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Prescription]:
    require_role(user, "patient")
    statement = (
        select(Prescription)
        .join(Encounter)
        .join(Patient)
        .where(Patient.user_id == user.id)
        .options(selectinload(Prescription.items))
        .order_by(Prescription.created_at.desc())
    )
    prescriptions = list(db.scalars(statement).all())
    for prescription in prescriptions:
        db.add(AccessAudit(user_id=user.id, prescription_id=prescription.id, action="patient_view"))
    if prescriptions:
        db.commit()
    return prescriptions


@router.get("/{prescription_id}", response_model=PrescriptionRead)
def get_prescription(
    prescription_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Prescription:
    require_role(user, "clinician", "admin")
    statement = (
        select(Prescription)
        .where(Prescription.id == prescription_id)
        .options(selectinload(Prescription.items), selectinload(Prescription.encounter))
    )
    prescription = db.scalar(statement)
    if prescription is None:
        raise HTTPException(status_code=404, detail="Prescription not found")
    if user.role == "clinician" and prescription.encounter.clinician_id != user.id:
        raise HTTPException(status_code=403, detail="Not authorized for this encounter")
    db.add(AccessAudit(user_id=user.id, prescription_id=prescription.id, action="view"))
    db.commit()
    return prescription


@router.patch("/{prescription_id}/status", response_model=PrescriptionRead)
def update_prescription_status(
    prescription_id: int,
    body: PrescriptionStatusUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Prescription:
    prescription = db.scalar(
        select(Prescription)
        .where(Prescription.id == prescription_id)
        .options(selectinload(Prescription.encounter), selectinload(Prescription.items))
    )
    if prescription is None:
        raise HTTPException(status_code=404, detail="Prescription not found")
    if prescription.status != "active":
        raise HTTPException(status_code=409, detail="Only active prescriptions can change status")

    if body.status == "cancelled":
        require_role(user, "clinician", "admin")
        if user.role == "clinician" and prescription.encounter.clinician_id != user.id:
            raise HTTPException(status_code=403, detail="You can only cancel prescriptions for your own encounters")
    else:
        require_role(user, "pharmacist", "admin")
        if user.role == "pharmacist":
            redeemed_share = db.scalar(
                select(PrescriptionShare.id).where(
                    PrescriptionShare.prescription_id == prescription.id,
                    PrescriptionShare.redeemed_by_user_id == user.id,
                    PrescriptionShare.redeemed_at.is_not(None),
                )
            )
            if redeemed_share is None:
                raise HTTPException(
                    status_code=403,
                    detail="You can mark a prescription fulfilled only after redeeming its share",
                )

    prescription.status = body.status
    now = datetime.now(timezone.utc)
    if body.status == "cancelled":
        # Invalidate all unredeemed shares so a cancelled prescription cannot still be dispensed.
        db.execute(
            update(PrescriptionShare)
            .where(
                PrescriptionShare.prescription_id == prescription.id,
                PrescriptionShare.redeemed_at.is_(None),
                PrescriptionShare.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
    db.add(
        AccessAudit(
            user_id=user.id,
            prescription_id=prescription.id,
            action=f"status_{body.status}",
        )
    )
    db.commit()
    db.refresh(prescription)
    return prescription


@router.get("/{prescription_id}/audit", response_model=list[PrescriptionAuditRead])
def get_prescription_audit(
    prescription_id: int,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[PrescriptionAuditRead]:
    statement = (
        select(Prescription)
        .where(Prescription.id == prescription_id)
        .options(selectinload(Prescription.encounter))
    )
    prescription = db.scalar(statement)
    if prescription is None:
        raise HTTPException(status_code=404, detail="Prescription not found")
    if user.role == "patient":
        patient = db.get(Patient, prescription.encounter.patient_id)
        if patient is None or patient.user_id != user.id:
            raise HTTPException(status_code=404, detail="Prescription not found")
    elif user.role == "clinician":
        if prescription.encounter.clinician_id != user.id:
            raise HTTPException(status_code=404, detail="Prescription not found")
    elif user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to view this audit history")

    rows = db.execute(
        select(AccessAudit, User)
        .join(User, User.id == AccessAudit.user_id)
        .where(AccessAudit.prescription_id == prescription_id)
        .order_by(AccessAudit.occurred_at, AccessAudit.id)
    ).all()
    return [
        PrescriptionAuditRead(
            id=audit.id,
            actor_user_id=actor.id,
            actor_name=actor.display_name,
            actor_role=actor.role,
            action=audit.action,
            occurred_at=audit.occurred_at,
        )
        for audit, actor in rows
    ]
