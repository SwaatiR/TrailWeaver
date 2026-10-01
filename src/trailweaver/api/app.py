"""FastAPI application factory for TrailWeaver investigation results."""

import logging
import os
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from trailweaver.api.schemas import (
    BlastRadiusAnalysisResponse,
    BlastRadiusResponse,
    BlastRadiusUnavailableResponse,
    GraphResponse,
    GuidanceResponse,
    HealthResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
    MitreResponse,
    RiskResponse,
)
from trailweaver.api.service import (
    IncidentAnalysisService,
    IncidentNotFoundError,
    IncidentRepository,
    InMemoryIncidentRepository,
)
from trailweaver.api.sqlite_repository import (
    IncidentRepositoryError,
    SQLiteIncidentRepository,
)
from trailweaver.cloud_context import CloudContext
from trailweaver.observability import log_event
from trailweaver.runtime import validate_cors_origins

_NO_CLOUD_CONTEXT_REASON = (
    "Blast-radius analysis is unavailable because no cloud context is loaded."
)
_DEFAULT_FRONTEND_ORIGIN = "http://localhost:5173"
_CORS_ORIGINS_ENV = "TRAILWEAVER_CORS_ORIGINS"
_LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(_application: FastAPI) -> AsyncIterator[None]:
    log_event(_LOGGER, logging.INFO, "api_started")
    yield
    log_event(_LOGGER, logging.INFO, "api_stopped")


def _cors_origins(configured: Iterable[str] | None) -> list[str]:
    """Resolve explicit or environment-provided frontend origins safely."""

    if configured is None:
        environment_value = os.getenv(_CORS_ORIGINS_ENV, _DEFAULT_FRONTEND_ORIGIN)
        candidates = environment_value.split(",")
    else:
        candidates = list(configured)

    origins = tuple(dict.fromkeys(origin.strip() for origin in candidates if origin.strip()))
    return list(validate_cors_origins(origins))


def create_app(
    *,
    repository: IncidentRepository | None = None,
    cloud_context: CloudContext | None = None,
    service: IncidentAnalysisService | None = None,
    cors_origins: Iterable[str] | None = None,
) -> FastAPI:
    """Create a testable API with explicitly injected data or application services."""

    if service is not None and (repository is not None or cloud_context is not None):
        raise ValueError("Inject service or repository/cloud_context, not both")

    incident_service = (
        service
        if service is not None
        else IncidentAnalysisService(
            repository if repository is not None else InMemoryIncidentRepository(),
            cloud_context=cloud_context,
        )
    )
    application = FastAPI(
        title="TrailWeaver API",
        version="1.0.0",
        lifespan=_lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(cors_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Accept", "Content-Type"],
    )

    @application.exception_handler(IncidentRepositoryError)
    async def repository_unavailable(
        _request: Request, error: IncidentRepositoryError
    ) -> JSONResponse:
        log_event(
            _LOGGER,
            logging.ERROR,
            "api_repository_unavailable",
            error_type=type(error).__name__,
        )
        return JSONResponse(
            status_code=503,
            content={"detail": "Incident storage is unavailable"},
        )

    @application.middleware("http")
    async def operational_middleware(request: Request, call_next) -> Response:
        started = perf_counter()
        try:
            response = await call_next(request)
        except Exception as error:
            log_event(
                _LOGGER,
                logging.ERROR,
                "http_request_failed",
                method=request.method,
                route=_route_template(request),
                duration_ms=round((perf_counter() - started) * 1000, 3),
                error_type=type(error).__name__,
            )
            raise
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.path not in {"/health", "/ready"}:
            log_event(
                _LOGGER,
                logging.INFO,
                "http_request_completed",
                method=request.method,
                route=_route_template(request),
                status=response.status_code,
                duration_ms=round((perf_counter() - started) * 1000, 3),
            )
        return response

    def incident_not_found(error: IncidentNotFoundError) -> HTTPException:
        return HTTPException(status_code=404, detail=f"Incident {error.args[0]!r} not found")

    @application.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @application.get("/ready", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        incident_service.check_readiness()
        return HealthResponse(status="ok")

    @application.get(
        "/api/v1/incidents",
        response_model=list[IncidentSummaryResponse],
    )
    async def list_incidents() -> list[IncidentSummaryResponse]:
        return [
            IncidentSummaryResponse.from_domain(incident)
            for incident in incident_service.list_incidents()
        ]

    @application.get(
        "/api/v1/incidents/{incident_id}",
        response_model=IncidentDetailResponse,
    )
    async def get_incident(incident_id: str) -> IncidentDetailResponse:
        try:
            return IncidentDetailResponse.from_domain(
                incident_service.get_incident(incident_id)
            )
        except IncidentNotFoundError as error:
            raise incident_not_found(error) from error

    @application.get(
        "/api/v1/incidents/{incident_id}/risk",
        response_model=RiskResponse,
    )
    async def get_risk(incident_id: str) -> RiskResponse:
        try:
            return RiskResponse.from_domain(incident_service.assess_risk(incident_id))
        except IncidentNotFoundError as error:
            raise incident_not_found(error) from error

    @application.get(
        "/api/v1/incidents/{incident_id}/mitre",
        response_model=MitreResponse,
    )
    async def get_mitre(incident_id: str) -> MitreResponse:
        try:
            return MitreResponse.from_domain(incident_service.map_mitre(incident_id))
        except IncidentNotFoundError as error:
            raise incident_not_found(error) from error

    @application.get(
        "/api/v1/incidents/{incident_id}/graph",
        response_model=GraphResponse,
    )
    async def get_graph(incident_id: str) -> GraphResponse:
        try:
            return GraphResponse.from_domain(incident_service.build_graph(incident_id))
        except IncidentNotFoundError as error:
            raise incident_not_found(error) from error

    @application.get(
        "/api/v1/incidents/{incident_id}/blast-radius",
        response_model=BlastRadiusResponse,
    )
    async def get_blast_radius(incident_id: str) -> BlastRadiusResponse:
        try:
            result = incident_service.analyze_blast_radius(incident_id)
        except IncidentNotFoundError as error:
            raise incident_not_found(error) from error
        if result is None:
            return BlastRadiusUnavailableResponse(reason=_NO_CLOUD_CONTEXT_REASON)
        return BlastRadiusAnalysisResponse.from_domain(result)

    @application.get(
        "/api/v1/incidents/{incident_id}/guidance",
        response_model=GuidanceResponse,
    )
    async def get_guidance(incident_id: str) -> GuidanceResponse:
        try:
            return GuidanceResponse.from_domain(
                incident_service.provide_guidance(incident_id)
            )
        except IncidentNotFoundError as error:
            raise incident_not_found(error) from error

    return application


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    return template if isinstance(template, str) else "unmatched"


def create_persistent_app(
    database_path: str | Path,
    *,
    cloud_context: CloudContext | None = None,
    cors_origins: Iterable[str] | None = None,
) -> FastAPI:
    """Create an API backed by an explicitly configured SQLite file.

    The caller controls when the repository is constructed; importing this module
    and the default ``app`` never creates a database.
    """

    return create_app(
        repository=SQLiteIncidentRepository(database_path),
        cloud_context=cloud_context,
        cors_origins=cors_origins,
    )


app = create_app()
