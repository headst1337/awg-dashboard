from __future__ import annotations

import os
import secrets
import threading
from dataclasses import asdict
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from .errors import (
    AwgDashboardError,
    ClientNotFoundError,
    ConflictError,
    DockerRuntimeError,
    NotInstalledError,
    ReconciliationError,
    ValidationError,
)
from .models import DEFAULT_IMAGE, AwgProtocolParameters, AwgSettings
from .service import AwgManager


class AwgParametersPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    junk_packet_count: int = 4
    junk_packet_min_size: int = 10
    junk_packet_max_size: int = 50
    init_packet_junk_size: int = 12
    response_packet_junk_size: int = 12
    cookie_reply_packet_junk_size: int = 12
    transport_packet_junk_size: int = 12
    init_packet_magic_header: str = "1"
    response_packet_magic_header: str = "2"
    underload_packet_magic_header: str = "3"
    transport_packet_magic_header: str = "4"
    special_junk_1: str = (
        "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001"
        "c00c000100010000105a00044d583737>"
    )
    special_junk_2: str = ""
    special_junk_3: str = ""
    special_junk_4: str = ""
    special_junk_5: str = ""
    header_protection_key: str = ""
    content_padding_addition: str = "10-100"
    rekey_after_time: str = "100-120"
    rekey_timeout: str = "3-7"
    reject_after_time: str = "150-180"
    keepalive_timeout: str = "5-15"
    max_handshake_attempts: str = "15-20"
    random_trailers: str = "on"
    disable_cookies: str = "on"

    def to_domain(self) -> AwgProtocolParameters:
        return AwgProtocolParameters(**self.model_dump())


class AwgSettingsPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_host: str
    listen_port: int = 55424
    subnet: str = "10.8.1.0/24"
    dns_servers: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "8.8.4.4"]
    )
    allowed_ips: list[str] = Field(default_factory=lambda: ["0.0.0.0/0"])
    mtu: int = 1376
    persistent_keepalive: int = 25
    protocol_version: str = "3.1"
    image: str = DEFAULT_IMAGE
    parameters: AwgParametersPayload = Field(
        default_factory=AwgParametersPayload
    )

    def to_domain(self) -> AwgSettings:
        values = self.model_dump(exclude={"parameters"})
        values["dns_servers"] = tuple(self.dns_servers)
        values["allowed_ips"] = tuple(self.allowed_ips)
        values["parameters"] = self.parameters.to_domain()
        return AwgSettings(**values)


class CreateClientPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    allowed_ips: list[str] | None = None


class UpgradePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    image: str


def create_app(
    *,
    manager: AwgManager | None = None,
    api_token: str | None = None,
) -> FastAPI:
    app = FastAPI(
        title="AWG Dashboard API",
        version="0.1.0",
        description="Local management API for an AmneziaWG Docker container.",
        redoc_url=None,
    )
    app.state.manager = manager
    app.state.manager_lock = threading.Lock()
    app.state.api_token = api_token

    bearer_scheme = HTTPBearer(auto_error=False)

    def get_manager(request: Request) -> AwgManager:
        current = request.app.state.manager
        if current is not None:
            return current
        with request.app.state.manager_lock:
            current = request.app.state.manager
            if current is None:
                state_dir = os.environ.get(
                    "AWG_DASHBOARD_STATE_DIR", "/var/lib/awg-dashboard"
                )
                current = AwgManager(state_dir=state_dir)
                request.app.state.manager = current
        return current

    def require_api_token(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(
            bearer_scheme
        ),
    ) -> None:
        expected = request.app.state.api_token or os.environ.get(
            "AWG_DASHBOARD_API_TOKEN"
        )
        if not expected:
            raise HTTPException(
                status_code=503,
                detail="API authentication is not configured",
            )
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not secrets.compare_digest(
            credentials.credentials.encode("utf-8"), expected.encode("utf-8")
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    router = APIRouter(
        prefix="/api/v1",
        dependencies=[Depends(require_api_token)],
    )

    @app.get("/healthz", tags=["health"])
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/status", tags=["server"])
    def get_status(
        awg_manager: AwgManager = Depends(get_manager),
    ) -> dict[str, Any]:
        return asdict(awg_manager.status())

    @router.post("/server/install", status_code=201, tags=["server"])
    def install_server(
        payload: AwgSettingsPayload,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> dict[str, Any]:
        return asdict(awg_manager.install(payload.to_domain()))

    @router.put("/server/settings", tags=["server"])
    def update_server_settings(
        payload: AwgSettingsPayload,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> dict[str, Any]:
        return asdict(awg_manager.update_settings(payload.to_domain()))

    @router.post("/server/upgrade", tags=["server"])
    def upgrade_server(
        payload: UpgradePayload,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> dict[str, Any]:
        return asdict(awg_manager.upgrade(payload.image))

    @router.get("/clients", tags=["clients"])
    def list_clients(
        awg_manager: AwgManager = Depends(get_manager),
    ) -> list[dict[str, Any]]:
        return [asdict(client) for client in awg_manager.list_clients()]

    @router.post("/clients", status_code=201, tags=["clients"])
    def create_client(
        payload: CreateClientPayload,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> dict[str, Any]:
        return asdict(
            awg_manager.create_client(
                payload.name,
                allowed_ips=(
                    tuple(payload.allowed_ips)
                    if payload.allowed_ips is not None
                    else None
                ),
            )
        )

    @router.get("/clients/{client_id}/config", tags=["clients"])
    def get_client_config(
        client_id: str,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> Response:
        return Response(
            content=awg_manager.get_client_config(client_id),
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="client.conf"',
                "Cache-Control": "no-store",
            },
        )

    @router.get("/clients/{client_id}/qr.svg", tags=["clients"])
    def get_client_qr(
        client_id: str,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> Response:
        return Response(
            content=awg_manager.get_client_qr_svg(client_id),
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    @router.delete("/clients/{client_id}", status_code=204, tags=["clients"])
    def revoke_client(
        client_id: str,
        awg_manager: AwgManager = Depends(get_manager),
    ) -> Response:
        awg_manager.revoke_client(client_id)
        return Response(status_code=204)

    app.include_router(router)

    @app.exception_handler(AwgDashboardError)
    async def handle_awg_error(
        _request: Request,
        error: AwgDashboardError,
    ) -> JSONResponse:
        if isinstance(error, ValidationError):
            status_code = 422
        elif isinstance(error, ConflictError):
            status_code = 409
        elif isinstance(error, (ClientNotFoundError, NotInstalledError)):
            status_code = 404
        elif isinstance(error, DockerRuntimeError):
            status_code = 503
        else:
            status_code = 500

        detail = (
            str(error)
            if status_code < 500 or isinstance(error, ReconciliationError)
            else "Internal AWG manager error"
        )
        return JSONResponse(status_code=status_code, content={"detail": detail})

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        # Do not echo request values: settings can contain cryptographic keys.
        safe_errors = [
            {key: item[key] for key in ("loc", "msg", "type") if key in item}
            for item in error.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": safe_errors})

    return app


app = create_app()
