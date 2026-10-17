from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import Base, apply_local_schema_updates, engine
from app.config import settings, validate_runtime_security
from app import models  # noqa: F401 - register models with SQLAlchemy metadata
from app.auth import router as auth_router
from app.routers.encounters import router as encounters_router
from app.routers.patients import router as patients_router
from app.routers.prescriptions import router as prescriptions_router
from app.routers.prescription_shares import router as prescription_shares_router
from app.routers.prescription_shares import redeem_router as prescription_share_redeem_router

validate_runtime_security()
is_development = settings.app_env.strip().lower() == "development"
app = FastAPI(
    title="Healthcare Records API",
    version="0.1.0",
    docs_url="/docs" if is_development else None,
    redoc_url="/redoc" if is_development else None,
    openapi_url="/openapi.json" if is_development else None,
)

# Convenient for local development. Use Alembic migrations for shared environments.
apply_local_schema_updates()
Base.metadata.create_all(bind=engine)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/") or request.url.path in {"/patient", "/pharmacy", "/register"}:
        response.headers["Cache-Control"] = "no-store"
    return response

app.include_router(auth_router, prefix="/api/v1")
app.include_router(patients_router, prefix="/api/v1")
app.include_router(encounters_router, prefix="/api/v1")
app.include_router(prescriptions_router, prefix="/api/v1")
app.include_router(prescription_shares_router, prefix="/api/v1")
app.include_router(prescription_share_redeem_router, prefix="/api/v1")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/patient", include_in_schema=False)
def patient_app() -> FileResponse:
    return FileResponse(STATIC_DIR / "patient.html")


@app.get("/register", include_in_schema=False)
def registration_app() -> FileResponse:
    return FileResponse(STATIC_DIR / "register.html")


@app.get("/pharmacy", include_in_schema=False)
def pharmacy_app() -> FileResponse:
    return FileResponse(STATIC_DIR / "pharmacy.html")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
