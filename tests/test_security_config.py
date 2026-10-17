import hashlib

import pytest
from cryptography.fernet import Fernet

from app.auth import hash_password, password_needs_rehash, verify_password
from app.config import Settings, settings, validate_runtime_security
from app.models import EncryptedText


def test_new_password_hash_uses_stronger_scrypt_profile_and_accepts_old_profile():
    new_hash = hash_password("sample password for security test")
    assert new_hash.startswith("scrypt$16384$8$5$")
    assert verify_password("sample password for security test", new_hash)
    assert not verify_password("wrong password", new_hash)
    assert not password_needs_rehash(new_hash)

    salt = b"legacy-test-salt"
    old_hash = hashlib.scrypt(
        b"old profile password", salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    old_encoded = f"scrypt$16384$8$1${salt.hex()}${old_hash.hex()}"
    assert verify_password("old profile password", old_encoded)
    assert password_needs_rehash(old_encoded)


def test_production_settings_reject_dev_auth_and_weak_jwt_secret():
    dev_auth = Settings(
        app_env="production",
        enable_dev_auth=True,
        jwt_secret="long-enough-random-secret-for-prod",
    )
    with pytest.raises(RuntimeError, match="ENABLE_DEV_AUTH"):
        validate_runtime_security(dev_auth)

    weak_secret = Settings(
        app_env="production",
        enable_dev_auth=False,
        jwt_secret="short",
    )
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        validate_runtime_security(weak_secret)

    valid = Settings(
        app_env="production",
        enable_dev_auth=False,
        jwt_secret="a-long-unique-random-secret-value-for-test",
        data_encryption_key=Fernet.generate_key().decode("ascii"),
        smtp_host="smtp.example.test",
        smtp_from="health@example.test",
    )
    validate_runtime_security(valid)


def test_health_text_is_encrypted_and_legacy_plaintext_remains_readable(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "data_encryption_key", key)
    encrypted_type = EncryptedText()
    stored = encrypted_type.process_bind_param("synthetic test diagnosis", None)
    assert stored.startswith("enc:v1:")
    assert "synthetic test diagnosis" not in stored
    assert encrypted_type.process_result_value(stored, None) == "synthetic test diagnosis"
    assert encrypted_type.process_result_value("old plaintext record", None) == "old plaintext record"

    monkeypatch.setattr(settings, "data_encryption_key", "")
    with pytest.raises(RuntimeError, match="requires DATA_ENCRYPTION_KEY"):
        encrypted_type.process_result_value(stored, None)


def test_security_headers_are_set(api):
    client, _ = api
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
