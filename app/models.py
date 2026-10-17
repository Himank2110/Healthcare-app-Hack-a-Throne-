from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.config import settings


class EncryptedText(TypeDecorator[str]):
    """Encrypt selected health-record text when DATA_ENCRYPTION_KEY is configured."""

    impl = Text
    cache_ok = False
    prefix = "enc:v1:"

    def _fernet(self) -> Fernet | None:
        key = settings.data_encryption_key
        return Fernet(key.encode("ascii")) if key else None

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        fernet = self._fernet()
        if fernet is None:
            return value
        encrypted = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return self.prefix + encrypted

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None or not value.startswith(self.prefix):
            return value
        fernet = self._fernet()
        if fernet is None:
            raise RuntimeError("Encrypted health data requires DATA_ENCRYPTION_KEY")
        try:
            return fernet.decrypt(value[len(self.prefix):].encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            raise RuntimeError("Health data could not be decrypted; check DATA_ENCRYPTION_KEY") from None


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    username: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    token_version: Mapped[int] = mapped_column(default=0)
    status: Mapped[str] = mapped_column(String(24), default="active", index=True)
    requested_role: Mapped[str | None] = mapped_column(String(32))
    organization_type: Mapped[str | None] = mapped_column(String(24))
    organization_name: Mapped[str | None] = mapped_column(String(160))


class Patient(Base):
    __tablename__ = "patients"

    id: Mapped[int] = mapped_column(primary_key=True)
    display_name: Mapped[str] = mapped_column(EncryptedText())
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), unique=True)


class Encounter(Base):
    __tablename__ = "encounters"

    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("patients.id"), index=True)
    clinician_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    diagnosis: Mapped[str] = mapped_column(EncryptedText())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    prescriptions: Mapped[list["Prescription"]] = relationship(back_populates="encounter")


class Prescription(Base):
    __tablename__ = "prescriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    encounter_id: Mapped[int] = mapped_column(ForeignKey("encounters.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    encounter: Mapped[Encounter] = relationship(back_populates="prescriptions")
    items: Mapped[list["PrescriptionItem"]] = relationship(back_populates="prescription", cascade="all, delete-orphan")


class PrescriptionItem(Base):
    __tablename__ = "prescription_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    prescription_id: Mapped[int] = mapped_column(ForeignKey("prescriptions.id"), index=True)
    medicine: Mapped[str] = mapped_column(EncryptedText())
    instructions: Mapped[str] = mapped_column(EncryptedText())

    prescription: Mapped[Prescription] = relationship(back_populates="items")


class AccessAudit(Base):
    __tablename__ = "access_audit"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    prescription_id: Mapped[int] = mapped_column(ForeignKey("prescriptions.id"), index=True)
    action: Mapped[str] = mapped_column(String(40))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PrescriptionShare(Base):
    __tablename__ = "prescription_shares"

    id: Mapped[int] = mapped_column(primary_key=True)
    prescription_id: Mapped[int] = mapped_column(ForeignKey("prescriptions.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    redeemed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
