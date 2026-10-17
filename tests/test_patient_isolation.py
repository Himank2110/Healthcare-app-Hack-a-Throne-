from datetime import datetime, timedelta, timezone

from jose import jwt

from app.config import settings


def auth_headers(user_id: int, role: str = "patient") -> dict[str, str]:
    token = jwt.encode(
        {
            "sub": str(user_id),
            "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    return {"Authorization": f"Bearer {token}"}


def test_clinician_can_cancel_own_prescription_and_invalidates_unredeemed_share(api):
    client, ids = api
    patient_headers = auth_headers(ids["owner_user"])
    clinician_headers = auth_headers(ids["clinician_user"], "clinician")

    share = client.post(
        f"/api/v1/prescriptions/{ids['owner_prescription']}/share",
        headers=patient_headers,
    )
    assert share.status_code == 201

    cancelled = client.patch(
        f"/api/v1/prescriptions/{ids['owner_prescription']}/status",
        headers=clinician_headers,
        json={"status": "cancelled"},
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"

    pharmacy_headers = auth_headers(ids["pharmacist_user"], "pharmacist")
    redeem = client.post(
        "/api/v1/prescription-shares/redeem",
        headers=pharmacy_headers,
        json={"share_token": share.json()["share_token"]},
    )
    assert redeem.status_code == 410

    audit = client.get(
        f"/api/v1/prescriptions/{ids['owner_prescription']}/audit",
        headers=patient_headers,
    )
    assert audit.status_code == 200
    actions = [row["action"] for row in audit.json()]
    assert "share_created" in actions
    assert "status_cancelled" in actions
    assert any(row["actor_role"] == "clinician" and row["actor_name"] == "clinician-demo" for row in audit.json())

    other_audit = client.get(
        f"/api/v1/prescriptions/{ids['owner_prescription']}/audit",
        headers=auth_headers(ids["other_user"]),
    )
    assert other_audit.status_code == 404


def test_pharmacist_can_mark_only_redeemed_share_fulfilled(api):
    client, ids = api
    patient_headers = auth_headers(ids["owner_user"])
    pharmacist_headers = auth_headers(ids["pharmacist_user"], "pharmacist")
    prescription_id = ids["owner_prescription"]

    before_redeem = client.patch(
        f"/api/v1/prescriptions/{prescription_id}/status",
        headers=pharmacist_headers,
        json={"status": "fulfilled"},
    )
    assert before_redeem.status_code == 403

    share = client.post(
        f"/api/v1/prescriptions/{prescription_id}/share",
        headers=patient_headers,
    )
    redeemed = client.post(
        "/api/v1/prescription-shares/redeem",
        headers=pharmacist_headers,
        json={"share_token": share.json()["share_token"]},
    )
    assert redeemed.status_code == 200

    fulfilled = client.patch(
        f"/api/v1/prescriptions/{prescription_id}/status",
        headers=pharmacist_headers,
        json={"status": "fulfilled"},
    )
    assert fulfilled.status_code == 200
    assert fulfilled.json()["status"] == "fulfilled"

    audit = client.get(
        f"/api/v1/prescriptions/{prescription_id}/audit",
        headers=patient_headers,
    )
    assert audit.status_code == 200
    assert [row["action"] for row in audit.json()] == ["share_created", "share_redeemed", "status_fulfilled"]
    assert audit.json()[-1]["actor_role"] == "pharmacist"


def test_patient_lists_only_their_own_records(api):
    client, ids = api
    owner_headers = auth_headers(ids["owner_user"])
    other_headers = auth_headers(ids["other_user"])

    owner_profile = client.get("/api/v1/patients/me", headers=owner_headers)
    other_profile = client.get("/api/v1/patients/me", headers=other_headers)
    assert owner_profile.status_code == 200
    assert owner_profile.json()["id"] == ids["owner_patient"]
    assert other_profile.status_code == 200
    assert other_profile.json()["id"] == ids["other_patient"]

    owner_prescriptions = client.get("/api/v1/prescriptions/mine", headers=owner_headers)
    other_prescriptions = client.get("/api/v1/prescriptions/mine", headers=other_headers)
    assert owner_prescriptions.status_code == 200
    assert [p["id"] for p in owner_prescriptions.json()] == [ids["owner_prescription"]]
    assert other_prescriptions.status_code == 200
    assert [p["id"] for p in other_prescriptions.json()] == [ids["other_prescription"]]

    owner_encounters = client.get("/api/v1/encounters/mine", headers=owner_headers)
    other_encounters = client.get("/api/v1/encounters/mine", headers=other_headers)
    assert owner_encounters.status_code == 200
    assert [e["id"] for e in owner_encounters.json()] == [ids["owner_encounter"]]
    assert other_encounters.status_code == 200
    assert [e["id"] for e in other_encounters.json()] == [ids["other_encounter"]]


def test_patient_cannot_create_a_share_for_another_patients_prescription(api):
    client, ids = api
    other_headers = auth_headers(ids["other_user"])

    response = client.post(
        f"/api/v1/prescriptions/{ids['owner_prescription']}/share",
        headers=other_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Prescription not found"

