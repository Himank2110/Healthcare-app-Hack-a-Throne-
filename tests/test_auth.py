from app.config import settings


def test_patient_can_register_and_log_in(api):
    client, _ = api
    registration = {
        "username": "new.patient",
        "email": "New.Patient@example.test",
        "password": "correct-horse-example-71",
        "display_name": "New patient",
        "role": "patient",
    }

    created = client.post("/api/v1/auth/register", json=registration)
    assert created.status_code == 201
    assert created.json()["role"] == "patient"
    assert "password" not in created.json()

    token = created.json()["access_token"]
    profile = client.get(
        "/api/v1/patients/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert profile.status_code == 200
    assert profile.json()["display_name"] == "New patient"

    logged_in = client.post(
        "/api/v1/auth/login",
        json={"identifier": "new.patient@example.test", "password": registration["password"]},
    )
    assert logged_in.status_code == 200
    assert logged_in.json()["role"] == "patient"


def test_registration_requires_a_supported_role_and_password_is_checked(api):
    client, _ = api
    registration = {
        "username": "self-appointed",
        "email": "self-appointed@example.test",
        "password": "a-long-enough-test-password",
        "display_name": "Attempted staff account",
        "role": "pharmacist",
        "organization_type": "pharmacy",
        "organization_name": "Example Pharmacy",
    }
    registered = client.post("/api/v1/auth/register", json=registration)
    assert registered.status_code == 201
    assert registered.json()["role"] == "pending"
    assert registered.json()["requested_role"] == "pharmacist"
    assert registered.json()["status"] == "pending"
    assert registered.json()["access_token"] is None
    assert registered.json()["organization_name"] == "Example Pharmacy"
    bad_password = client.post(
        "/api/v1/auth/login",
        json={"identifier": registration["email"], "password": "wrong-password"},
    )
    assert bad_password.status_code == 401
    assert bad_password.json()["detail"] == "Invalid email or password"


def test_admin_bootstrap_is_one_time_and_admin_can_provision_staff(api, monkeypatch):
    client, _ = api
    monkeypatch.setattr(settings, "bootstrap_admin_key", "test-bootstrap-secret")
    body = {
        "username": "test-admin",
        "email": "admin@example.test",
        "password": "a-strong-admin-test-password",
        "display_name": "Test admin",
    }
    bootstrapped = client.post(
        "/api/v1/auth/bootstrap-admin",
        headers={"X-Bootstrap-Key": "test-bootstrap-secret"},
        json=body,
    )
    assert bootstrapped.status_code == 201
    second_bootstrap = client.post(
        "/api/v1/auth/bootstrap-admin",
        headers={"X-Bootstrap-Key": "test-bootstrap-secret"},
        json={**body, "email": "second-admin@example.test"},
    )
    assert second_bootstrap.status_code == 409

    admin_login = client.post(
        "/api/v1/auth/login",
        json={"identifier": body["email"], "password": body["password"]},
    )
    admin_token = admin_login.json()["access_token"]
    staff = client.post(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "test-clinician",
            "email": "clinician@example.test",
            "password": "a-strong-clinician-password",
            "display_name": "Test clinician",
            "role": "clinician",
            "organization_type": "clinic",
            "organization_name": "Example Clinic",
        },
    )
    assert staff.status_code == 201
    assert staff.json()["role"] == "clinician"

    patient = client.post(
        "/api/v1/auth/register",
        json={
            "username": "non-admin",
            "email": "non-admin@example.test",
            "password": "a-strong-patient-password",
            "display_name": "Non-admin patient",
            "role": "patient",
        },
    )
    patient_headers = {"Authorization": f"Bearer {patient.json()['access_token']}"}
    forbidden = client.post(
        "/api/v1/auth/users",
        headers=patient_headers,
        json={
            "username": "attacker-pharmacist",
            "email": "attacker-pharmacist@example.test",
            "password": "a-strong-staff-password",
            "display_name": "Attempted staff account",
            "role": "pharmacist",
            "organization_type": "pharmacy",
            "organization_name": "Attempted Pharmacy",
        },
    )
    assert forbidden.status_code == 403


def test_clinic_registration_waits_for_admin_approval_then_can_sign_in(api, monkeypatch):
    client, _ = api
    monkeypatch.setattr(settings, "bootstrap_admin_key", "test-bootstrap-secret")
    admin_body = {
        "username": "approver",
        "email": "approver@example.test",
        "password": "a-strong-admin-test-password",
        "display_name": "Approver",
    }
    client.post(
        "/api/v1/auth/bootstrap-admin",
        headers={"X-Bootstrap-Key": "test-bootstrap-secret"},
        json=admin_body,
    )
    admin_token = client.post(
        "/api/v1/auth/login",
        json={"identifier": "approver", "password": admin_body["password"]},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    signup = client.post(
        "/api/v1/auth/register",
        json={
            "username": "dr-example",
            "email": "doctor@example.test",
            "password": "a-strong-doctor-test-password",
            "display_name": "Dr Example",
            "role": "clinician",
            "organization_type": "hospital",
            "organization_name": "Example Hospital",
        },
    )
    account = signup.json()
    assert signup.status_code == 201
    assert account["status"] == "pending"
    assert account["organization_type"] == "hospital"
    assert client.post(
        "/api/v1/auth/login",
        json={"identifier": "dr-example", "password": "a-strong-doctor-test-password"},
    ).status_code == 403

    pending = client.get("/api/v1/auth/pending-accounts", headers=headers)
    assert pending.status_code == 200
    assert any(row["id"] == account["id"] for row in pending.json())
    approved = client.post(f"/api/v1/auth/accounts/{account['id']}/approve", headers=headers)
    assert approved.status_code == 200
    assert approved.json()["role"] == "clinician"
    signed_in = client.post(
        "/api/v1/auth/login",
        json={"identifier": "dr-example", "password": "a-strong-doctor-test-password"},
    )
    assert signed_in.status_code == 200
    assert signed_in.json()["role"] == "clinician"


def test_password_recovery_is_one_time_and_invalidates_existing_tokens(api, monkeypatch):
    client, _ = api
    monkeypatch.setattr(settings, "app_env", "development")
    created = client.post(
        "/api/v1/auth/register",
        json={
            "username": "recover-user",
            "email": "recover@example.test",
            "password": "old-password-for-recovery",
            "display_name": "Recovery user",
            "role": "patient",
        },
    )
    old_token = created.json()["access_token"]

    requested = client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "recover@example.test"},
    )
    assert requested.status_code == 202
    assert "If an account exists" in requested.json()["message"]
    reset_token = requested.json()["dev_reset_token"]

    confirmed = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "new-password-for-recovery"},
    )
    assert confirmed.status_code == 200
    assert client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {old_token}"},
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/login",
        json={"identifier": "recover-user", "password": "old-password-for-recovery"},
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/login",
        json={"identifier": "recover-user", "password": "new-password-for-recovery"},
    ).status_code == 200
    assert client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "another-new-password-for-test"},
    ).status_code == 400


def test_login_is_throttled_after_repeated_bad_passwords(api):
    client, _ = api
    payload = {"identifier": "rate-limit-me", "password": "incorrect-password"}
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json=payload).status_code == 401
    limited = client.post("/api/v1/auth/login", json=payload)
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0
