from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.database import get_db
from app.models import Patient, User
from app.permissions import require_role
from app.schemas import PatientCreate, PatientRead

router = APIRouter(prefix="/patients", tags=["patients"])


@router.post("", response_model=PatientRead, status_code=201)
def create_patient(
    body: PatientCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Patient:
    require_role(user, "clinician", "admin")
    if body.user_id is not None:
        linked_user = db.get(User, body.user_id)
        if linked_user is None or linked_user.role != "patient":
            raise HTTPException(status_code=422, detail="user_id must refer to a patient account")
        if db.scalar(select(Patient).where(Patient.user_id == body.user_id)) is not None:
            raise HTTPException(status_code=409, detail="Patient account is already linked")
    patient = Patient(display_name=body.display_name, user_id=body.user_id)
    db.add(patient)
    db.commit()
    db.refresh(patient)
    return patient


@router.get("/me", response_model=PatientRead)
def get_my_patient_profile(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Patient:
    require_role(user, "patient")
    patient = db.scalar(select(Patient).where(Patient.user_id == user.id))
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient profile not found")
    return patient
