from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DevTokenRequest(BaseModel):
    role: str
    display_name: str = Field(default="demo-user", min_length=1, max_length=120)


class AccountCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=6, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)

    @field_validator("username", "email", mode="before")
    @classmethod
    def normalize_login_name(cls, value: str) -> str:
        return value.strip().lower()


class AccountRegistration(AccountCredentials):
    role: Literal["patient", "clinician", "pharmacist"]
    organization_type: Literal["clinic", "hospital", "pharmacy"] | None = None
    organization_name: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def validate_requested_role(self):
        if self.role == "patient":
            if self.organization_type is not None or self.organization_name:
                raise ValueError("Patient accounts do not include an organization")
        elif self.role == "clinician":
            if self.organization_type not in {"clinic", "hospital"} or not self.organization_name:
                raise ValueError("Clinicians must provide a clinic or hospital name")
        elif self.role == "pharmacist":
            if self.organization_type != "pharmacy" or not self.organization_name:
                raise ValueError("Pharmacists must provide their pharmacy name")
        return self


class StaffAccountCreate(AccountCredentials):
    role: Literal["clinician", "pharmacist"]
    organization_type: Literal["clinic", "hospital", "pharmacy"]
    organization_name: str = Field(min_length=1, max_length=160)

    @model_validator(mode="after")
    def validate_organization(self):
        if self.role == "clinician" and self.organization_type not in {"clinic", "hospital"}:
            raise ValueError("Clinicians must be associated with a clinic or hospital")
        if self.role == "pharmacist" and self.organization_type != "pharmacy":
            raise ValueError("Pharmacists must be associated with a pharmacy")
        return self


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("identifier", mode="before")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        return value.strip().lower()


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=6, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class PasswordResetResponse(BaseModel):
    message: str
    dev_reset_token: str | None = None


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)


class AccountRead(BaseModel):
    id: int
    username: str | None
    email: str | None
    display_name: str
    role: str
    status: str
    requested_role: str | None = None
    organization_type: str | None = None
    organization_name: str | None = None


class RegistrationRead(AccountRead):
    access_token: str | None = None
    message: str


class TokenRead(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    role: str


class PatientCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    user_id: int | None = None


class PatientRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    display_name: str


class EncounterCreate(BaseModel):
    patient_id: int
    diagnosis: str = Field(min_length=1, max_length=500)


class EncounterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    patient_id: int
    clinician_id: int
    diagnosis: str
    created_at: datetime


class PrescriptionItemCreate(BaseModel):
    medicine: str = Field(min_length=1, max_length=200)
    instructions: str = Field(min_length=1, max_length=500)


class PrescriptionCreate(BaseModel):
    encounter_id: int
    items: list[PrescriptionItemCreate] = Field(min_length=1)


class PrescriptionItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    medicine: str
    instructions: str


class PrescriptionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    encounter_id: int
    status: str
    created_at: datetime
    items: list[PrescriptionItemRead]


class PrescriptionStatusUpdate(BaseModel):
    status: Literal["cancelled", "fulfilled"]


class PrescriptionAuditRead(BaseModel):
    id: int
    actor_user_id: int
    actor_name: str
    actor_role: str
    action: str
    occurred_at: datetime


class PrescriptionShareCreate(BaseModel):
    share_id: int
    share_token: str
    qr_payload: str
    qr_code_data_uri: str
    expires_at: datetime


class PrescriptionShareRedeem(BaseModel):
    share_token: str = Field(min_length=20, max_length=200)


class PrescriptionShareRevokeRead(BaseModel):
    share_id: int
    status: str = "revoked"
