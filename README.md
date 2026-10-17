# Healthcare Records API starter

A small FastAPI backend scaffold for the prescription workflow described in the supplied presentation.

## Run locally

1. Activate the virtual environment created for this project.
2. For local development, copy `.env.example` to `.env`, set `JWT_SECRET` to a random secret, and set `ENABLE_DEV_AUTH=true` only if you want the demo screens and `/auth/dev-token` to work. Keep `APP_ENV=development` and do not expose this server to the internet. The default database URL uses local PostgreSQL; change it to SQLite for a quick local run if PostgreSQL is not installed.
3. Start the API with `uvicorn app.main:app`.
4. Open `http://127.0.0.1:8000/docs` for the API docs. `GET /health` does not require authentication.
5. Open `http://127.0.0.1:8000/register` to create a patient, clinician, or pharmacist account.
6. Open `http://127.0.0.1:8000/patient` for the patient screen, or `http://127.0.0.1:8000/pharmacy` for the pharmacist QR/NFC reader demo.

## Run automated checks

From the project folder, install the development dependencies and run the patient-isolation API tests:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

The tests use a temporary in-memory database. They check that each patient sees only their own profile, encounters, and prescriptions, and cannot create a share for another patient's prescription.

The local-only `POST /api/v1/auth/dev-token` endpoint issues a 30-minute token for a selected demo role. It is available only when `APP_ENV=development` and `ENABLE_DEV_AUTH=true`. Never enable it on a public or shared deployment. Before production, disable it and connect a trusted identity provider. Do not use real patient data.

## Registration and password accounts

- `POST /api/v1/auth/register` accepts a username, email, password, display name, and requested role: `patient`, `clinician`, or `pharmacist`. Passwords must be at least 12 characters and are stored as salted scrypt hashes.
- The registration form is at `/register`. It shows clinic/hospital fields for clinicians and pharmacy-name fields for pharmacists. A newly registered patient is sent to the patient portal with their sign-in token.
- Patients are activated immediately and receive a bearer token. Clinicians must provide `organization_type` as `clinic` or `hospital`, plus `organization_name`. Pharmacists must provide `organization_type: "pharmacy"` and their shop name. These professional applications are stored as pending and receive no token until an admin approves them.
- `POST /api/v1/auth/login` accepts `identifier` (username or email) and password and returns a 30-minute bearer token for active accounts.
- Failed login attempts are throttled after 5 tries per identifier or 30 tries per client IP in a 15-minute window. The limiter is process-local for this one-instance learning server; a production deployment needs a shared rate-limit store at its gateway or service layer.
- `POST /api/v1/auth/password-reset/request` accepts an email and always returns a generic response. In development it also returns `dev_reset_token` so the flow can be tried in Swagger; that token is deliberately omitted outside development, where SMTP delivery must be configured.
- `POST /api/v1/auth/password-reset/confirm` accepts the one-time token and a new password. Tokens expire after 20 minutes. A successful reset invalidates existing access tokens and other reset tokens for that account. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM` for non-development mode; SMTP STARTTLS is required.
- `GET /api/v1/auth/me` returns the signed-in account's basic details.
- `POST /api/v1/auth/bootstrap-admin` creates the first password-based admin account. Before using it, set a long random `BOOTSTRAP_ADMIN_KEY` in `.env` and restart the server. Send the same value in the `X-Bootstrap-Key` header. This endpoint works once; after an admin exists it returns 409.
- An admin can review `GET /api/v1/auth/pending-accounts`, then approve with `POST /api/v1/auth/accounts/{account_id}/approve` or reject with `POST /api/v1/auth/accounts/{account_id}/reject`. `POST /api/v1/auth/users` remains available for admins to directly provision clinician or pharmacist accounts.

Organization names and professional identities are collected but not independently verified in this learning scaffold. The admin approval is a manual gate, not formal license verification. The patient and pharmacy demo pages still use the local `dev-token` flow; this account registration workflow is available through `/docs` and is not yet wired into those demo screens. Before handling real patient data, add email verification, password reset, login throttling, secure deployment settings, and a security review.

The patient and pharmacy demo pages still use the local `dev-token` flow; the email/password API is currently exercised through `/docs`. Before handling real patient data, add email verification, password reset, login throttling, secure deployment settings, and a security review.

## Current endpoints

- `POST /api/v1/patients`: clinician/admin creates a patient.
- `GET /api/v1/patients/me`: patient reads their linked profile.
- `POST /api/v1/encounters`: clinician/admin creates an encounter for a patient.
- `POST /api/v1/prescriptions`: clinician/admin creates a prescription for an encounter.
- `GET /api/v1/prescriptions/mine`: patient lists their prescriptions.
- `GET /api/v1/encounters/mine`: patient lists their encounters.
- `POST /api/v1/prescriptions/{id}/share`: patient creates a five-minute, single-use share token for their prescription.
- `POST /api/v1/prescription-shares/redeem`: authenticated pharmacist redeems the token and receives only that prescription.
- `POST /api/v1/prescription-shares/{share_id}/revoke`: patient cancels their unused share token before it expires.
- `GET /api/v1/prescriptions/{id}`: clinician can read their own encounters; admin can read any. Pharmacists must redeem a patient share token. Access events are recorded in `access_audit`.
- `PATCH /api/v1/prescriptions/{id}/status`: a clinician can cancel a prescription for their own encounter; a pharmacist can mark a prescription fulfilled after redeeming its share; an admin can perform either change. Only active prescriptions can change status. Cancelling invalidates outstanding unused shares.
- `GET /api/v1/prescriptions/{id}/audit`: the patient who owns the prescription, its clinician, or an admin can see the recorded events with the acting account's name and role. Events include views, shares created/revoked/redeemed, and status changes.

## Try the demo flow in `/docs`

With the API running and the local `.env` settings enabled:

1. Get a patient token from `POST /api/v1/auth/dev-token` with `{"role":"patient","display_name":"demo-patient"}`. Authorize, then call `GET /api/v1/patients/me` and note the patient profile `id`.
2. Get a clinician token with `{"role":"clinician","display_name":"demo-clinician"}`. Authorize, create an encounter for that patient ID, then create a prescription for the returned encounter ID.
3. Re-authorize with the patient token. Call `GET /api/v1/prescriptions/mine`, then create a share with `POST /api/v1/prescriptions/{prescription_id}/share` for one of the returned prescriptions. The response includes a `share_id` for revocation.
4. The share response contains an opaque `qr_payload`, a QR image, and an expiry time. The patient screen renders the QR or writes the same token to NFC when the browser reports Web NFC support; the token contains no prescription details.
5. If the patient changes their mind before redemption, call `POST /api/v1/prescription-shares/{share_id}/revoke` with the returned `share_id`. Otherwise, get a pharmacist token with `{"role":"pharmacist","display_name":"demo-pharmacist"}`. Authorize, then call `POST /api/v1/prescription-shares/redeem` with `{"share_token":"<value from qr_payload>"}`. It should return that prescription. A second redemption, revoked token, or expired token is rejected.

## Scope and next steps

This is a learning scaffold, not a production health-record system. The QR/NFC payload is a bearer token, so anyone who gets a copy can redeem it once before it expires; keep it short-lived and never include health details in it. Before real use, add trusted identity-provider integration, formal Alembic migrations, encrypted transport and storage, key management, rate limits, retention rules, security review, and jurisdiction-specific privacy review. Build public-health reports only from carefully aggregated data with re-identification protections.

The patient page uses the local development token endpoint. Browser NFC writing is only available on supported browsers/devices in a secure context (localhost counts for local development); unsupported devices keep the NFC button disabled. NFC availability is checked in the browser, while the server still handles expiry, single use, and cancellation.

The pharmacy page also uses the local development token endpoint. Camera QR scanning uses the browser's built-in `BarcodeDetector` when available and a locally hosted `jsQR` fallback otherwise; NFC uses Web NFC on supported devices. Both readers send the same opaque token to the pharmacist-only redeem endpoint. A manual token field is included as a development fallback.

## Security and privacy status

This remains a local learning prototype. It is **not ready for real patient information**. The backend now uses salted scrypt password hashes with a stronger work profile for new logins and upgrades older local hashes after successful sign-in. With `DATA_ENCRYPTION_KEY` set, patient display names, diagnoses, and prescription item details are encrypted in the database. It adds baseline browser security headers. Outside `APP_ENV=development`, startup rejects enabled development-token auth, a missing/placeholder JWT secret, or a missing/invalid data-encryption key, and Swagger/OpenAPI are disabled.

To enable local field encryption, generate a Fernet key with `\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`, then place it in `DATA_ENCRYPTION_KEY` in `.env`. Back up the database first, then encrypt existing rows with `\.venv\Scripts\python.exe -m scripts.encrypt_existing_records`. Keep the key backed up separately from the database. Losing the key makes those fields unreadable. The migration script does not rotate keys.

Field encryption protects the selected fields in database dumps, but it does not encrypt the entire SQLite file, WAL files, or backups. For a real deployment, use managed database/disk encryption and encrypted backups, keep keys in a secret manager or key vault, and serve the app only over HTTPS. The production host must also provide shared login throttling, monitoring, restricted admin access, recovery/retention procedures, and jurisdiction-specific privacy/security review. Email verification, MFA, password reset, and login throttling are not implemented here. Keep using synthetic records until those controls and an independent security review are in place.
