import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Keep importing the app from touching the developer's local SQLite database.
os.environ["DATABASE_URL"] = "sqlite://"

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Encounter, Patient, Prescription, PrescriptionItem, User  # noqa: E402


@pytest.fixture
def api() -> Iterator[tuple[TestClient, dict[str, int]]]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db() -> Iterator[Session]:
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    db = TestingSession()
    try:
        owner_user = User(role="patient", display_name="owner-demo")
        other_user = User(role="patient", display_name="other-demo")
        clinician = User(role="clinician", display_name="clinician-demo")
        pharmacist = User(role="pharmacist", display_name="pharmacist-demo")
        db.add_all([owner_user, other_user, clinician, pharmacist])
        db.flush()

        owner_patient = Patient(display_name="Owner demo", user_id=owner_user.id)
        other_patient = Patient(display_name="Other demo", user_id=other_user.id)
        db.add_all([owner_patient, other_patient])
        db.flush()

        owner_encounter = Encounter(
            patient_id=owner_patient.id,
            clinician_id=clinician.id,
            diagnosis="Synthetic owner encounter",
        )
        other_encounter = Encounter(
            patient_id=other_patient.id,
            clinician_id=clinician.id,
            diagnosis="Synthetic other encounter",
        )
        db.add_all([owner_encounter, other_encounter])
        db.flush()

        owner_prescription = Prescription(
            encounter_id=owner_encounter.id,
            items=[PrescriptionItem(medicine="Owner test item", instructions="Synthetic test only")],
        )
        other_prescription = Prescription(
            encounter_id=other_encounter.id,
            items=[PrescriptionItem(medicine="Other test item", instructions="Synthetic test only")],
        )
        db.add_all([owner_prescription, other_prescription])
        db.commit()

        ids = {
            "owner_user": owner_user.id,
            "other_user": other_user.id,
            "clinician_user": clinician.id,
            "pharmacist_user": pharmacist.id,
            "owner_patient": owner_patient.id,
            "other_patient": other_patient.id,
            "owner_encounter": owner_encounter.id,
            "other_encounter": other_encounter.id,
            "owner_prescription": owner_prescription.id,
            "other_prescription": other_prescription.id,
        }
        with TestClient(app) as client:
            yield client, ids
    finally:
        db.close()
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()

