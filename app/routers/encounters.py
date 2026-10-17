from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.database import get_db
from app.models import Encounter, Patient
from app.permissions import require_role
from app.schemas import EncounterCreate, EncounterRead

router = APIRouter(prefix="/encounters", tags=["encounters"])


@router.post("", response_model=EncounterRead, status_code=201)
def create_encounter(
    body: EncounterCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Encounter:
    require_role(user, "clinician", "admin")
    if db.get(Patient, body.patient_id) is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    encounter = Encounter(
        patient_id=body.patient_id,
        clinician_id=user.id,
        diagnosis=body.diagnosis,
    )
    db.add(encounter)
    db.commit()
    db.refresh(encounter)
    return encounter


@router.get("/mine", response_model=list[EncounterRead])
def list_my_encounters(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Encounter]:
    require_role(user, "patient")
    return list(
        db.scalars(
            select(Encounter)
            .join(Patient)
            .where(Patient.user_id == user.id)
            .order_by(Encounter.created_at.desc())
        ).all()
    )
