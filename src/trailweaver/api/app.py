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

from trailweaver.analysis_ledger import (
    AnalysisRunRepository,
    AnalysisRunRepositoryError,
    InMemoryAnalysisRunRepository,
)
from trailweaver.api.analysis import (
    ALLOWED_UPLOAD_CONTENT_TYPES,
    MAX_WEB_SOURCE_BYTES,
    S3AdapterFactory,
    UploadedContentError,
    analyze_s3_object,
    analyze_uploaded_bytes,
    default_s3_adapter_factory,
)
from trailweaver.api.execution import (
    InvestigationRunner,
    create_default_investigation_runner,
)
from trailweaver.api.schemas import (
    AnalysisResponse,
    BlastRadiusAnalysisResponse,
    BlastRadiusResponse,
    BlastRadiusUnavailableResponse,
    CapabilitiesResponse,
    ClearWorkspaceResponse,
    DemoResetResponse,
    GraphResponse,
    GuidanceResponse,
    HealthResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
    MitreResponse,
    RiskResponse,
    S3AnalysisRequest,
    S3PrefixAnalysisRequest,
    S3PrefixAnalysisResponse,
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
from trailweaver.aws_s3 import (
    S3CloudTrailAccessDeniedError,
    S3CloudTrailObjectNotFoundError,
    S3CloudTrailSourceError,
)
from trailweaver.cloud_context import CloudContext
from trailweaver.cloudtrail_ingestion import (
    CloudTrailIngestionError,
    CloudTrailSourceTooLargeError,
)
from trailweaver.event_ledger import (
    EventLedgerError,
    EventLedgerRepository,
    InMemoryEventLedger,
)
from trailweaver.observability import log_event
from trailweaver.runtime import validate_cors_origins
from trailweaver.signal_history import (
    InMemorySignalHistory,
    SignalHistoryError,
    SignalHistoryRepository,
)

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
    analysis_runner: InvestigationRunner | None = None,
    analysis_run_repository: AnalysisRunRepository | None = None,
    event_ledger_repository: EventLedgerRepository | None = None,
    signal_history_repository: SignalHistoryRepository | None = None,
    enable_analysis: bool = True,
    enable_s3_analysis: bool = True,
    demo_mode: bool = False,
    enable_demo_reset: bool = False,
    s3_adapter_factory: S3AdapterFactory | None = None,
) -> FastAPI:
    """Create a testable API with explicitly injected data or application services."""

    if service is not None and (repository is not None or cloud_context is not None):
        raise ValueError("Inject service or repository/cloud_context, not both")

    incident_repository = (
        repository if repository is not None else InMemoryIncidentRepository()
    )
    run_repository = (
        analysis_run_repository
        if analysis_run_repository is not None
        else (
            incident_repository
            if isinstance(incident_repository, SQLiteIncidentRepository)
            else InMemoryAnalysisRunRepository()
        )
    )
    event_ledger = (
        event_ledger_repository
        if event_ledger_repository is not None
        else (
            incident_repository
            if isinstance(incident_repository, SQLiteIncidentRepository)
            else InMemoryEventLedger()
        )
    )
    signal_history = (
        signal_history_repository
        if signal_history_repository is not None
        else (
            incident_repository
            if isinstance(incident_repository, SQLiteIncidentRepository)
            else InMemorySignalHistory()
        )
    )
    incident_service = (
        service
        if service is not None
        else IncidentAnalysisService(
            incident_repository,
            cloud_context=cloud_context,
        )
    )
    runner: InvestigationRunner | None = None
    if enable_analysis:
        runner = (
            analysis_runner
            if analysis_runner is not None or service is not None
            else create_default_investigation_runner(
                incident_repository,
                analysis_run_repository=run_repository,
                event_ledger_repository=event_ledger,
                signal_history_repository=signal_history,
            )
        )
    application = FastAPI(
        title="TrailWeaver API",
        version="1.0.0",
        lifespan=_lifespan,
    )
    application.state.s3_adapter_factory = (
        s3_adapter_factory
        if s3_adapter_factory is not None
        else default_s3_adapter_factory
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type"],
    )

    @application.exception_handler(AnalysisRunRepositoryError)
    @application.exception_handler(EventLedgerError)
    @application.exception_handler(SignalHistoryError)
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

    @application.get(
        "/api/v1/capabilities",
        response_model=CapabilitiesResponse,
    )
    async def get_capabilities() -> CapabilitiesResponse:
        return CapabilitiesResponse(
            file_analysis=runner is not None,
            s3_analysis=runner is not None and enable_s3_analysis,
            demo_mode=demo_mode,
        )

    if enable_demo_reset:

        @application.post(
            "/api/v1/demo/reset",
            response_model=DemoResetResponse,
        )
        async def reset_demo_workspace() -> DemoResetResponse:
            """Clear demo workspace incidents without touching anything else.

            This route only exists when the application was explicitly created
            with demo reset enabled. Production applications never register it,
            so no destructive capability is exposed there.
            """

            if isinstance(incident_repository, InMemoryIncidentRepository):
                incident_repository.clear_incidents()
                # Demo replay support: the synthetic demo must process its
                # fixture again from scratch, so demo event-dedup and signal
                # history state reset here too. Production workspace clearing
                # deliberately keeps dedup history; run history is preserved
                # in both cases.
                if isinstance(event_ledger, InMemoryEventLedger):
                    event_ledger.clear()
                if isinstance(signal_history, InMemorySignalHistory):
                    signal_history.clear()
                    incident_repository.clear_emitted_correlations()
                return DemoResetResponse(status="ok", incidents=0)
            raise HTTPException(
                status_code=503,
                detail="Demo reset is unavailable on this API instance",
            )

    @application.post(
        "/api/v1/workspace/clear",
        response_model=ClearWorkspaceResponse,
    )
    async def clear_workspace() -> ClearWorkspaceResponse:
        """Remove every persisted incident from the current workspace.

        The operation affects only the incident repository already configured
        for this process: incident rows and their related correlation and
        signal rows. Source files, AWS resources, and the database file
        itself are never touched. Repository failures surface through the
        shared sanitized storage-unavailable handling.
        """

        incident_service.clear_workspace()
        return ClearWorkspaceResponse(status="ok", incidents=0)

    @application.post(
        "/api/v1/analyses/file",
        response_model=AnalysisResponse,
    )
    async def analyze_file_upload(request: Request) -> AnalysisResponse:
        if runner is None:
            raise HTTPException(
                status_code=503,
                detail="Web analysis is unavailable on this API instance",
            )
        content_type = (
            request.headers.get("content-type", "").split(";")[0].strip().lower()
        )
        if content_type not in ALLOWED_UPLOAD_CONTENT_TYPES:
            raise HTTPException(
                status_code=415,
                detail="Upload CloudTrail evidence as JSON or gzipped JSON",
            )
        declared_size = request.headers.get("content-length", "")
        if declared_size.isdigit() and int(declared_size) > MAX_WEB_SOURCE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Uploaded CloudTrail content exceeds the size limit",
            )
        payload = await request.body()
        if len(payload) > MAX_WEB_SOURCE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Uploaded CloudTrail content exceeds the size limit",
            )
        try:
            result = analyze_uploaded_bytes(
                payload,
                runner,
                source_label=request.query_params.get("source_label"),
            )
        except UploadedContentError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except CloudTrailSourceTooLargeError as error:
            raise HTTPException(status_code=413, detail=str(error)) from error
        except CloudTrailIngestionError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return AnalysisResponse.from_result(result)

    @application.post(
        "/api/v1/analyses/s3",
        response_model=AnalysisResponse,
    )
    async def analyze_s3_source(payload: S3AnalysisRequest) -> AnalysisResponse:
        if runner is None or not enable_s3_analysis:
            raise HTTPException(
                status_code=503,
                detail="S3 analysis is unavailable on this API instance",
            )
        bucket = payload.bucket.strip()
        key = payload.key.strip()
        if not bucket or not key:
            raise HTTPException(
                status_code=422,
                detail="S3 bucket and object key must be non-empty",
            )
        factory: S3AdapterFactory = application.state.s3_adapter_factory
        try:
            result = analyze_s3_object(
                factory(payload.region),
                runner,
                bucket=bucket,
                key=key,
                version_id=payload.version_id,
                source_label=payload.source_label,
            )
        except S3CloudTrailObjectNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except S3CloudTrailAccessDeniedError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        except S3CloudTrailSourceError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        except CloudTrailSourceTooLargeError as error:
            raise HTTPException(status_code=413, detail=str(error)) from error
        except CloudTrailIngestionError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return AnalysisResponse.from_result(result)

    @application.post(
        "/api/v1/analyses/s3-prefix",
        response_model=S3PrefixAnalysisResponse,
    )
    async def analyze_s3_prefix(payload: S3PrefixAnalysisRequest) -> S3PrefixAnalysisResponse:
        if runner is None or not enable_s3_analysis:
            raise HTTPException(
                status_code=503,
                detail="S3 analysis is unavailable on this API instance",
            )
        bucket = payload.bucket.strip()
        prefix = payload.prefix.strip()
        if not bucket or not prefix:
            raise HTTPException(
                status_code=422,
                detail="S3 bucket and object prefix must be non-empty",
            )
        factory: S3AdapterFactory = application.state.s3_adapter_factory
        try:
            result = factory(payload.region).analyze_prefix(
                runner,
                bucket=bucket,
                prefix=prefix,
                max_objects=payload.max_objects,
            )
        except S3CloudTrailSourceError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        return S3PrefixAnalysisResponse.from_analysis(result)

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

    repository = SQLiteIncidentRepository(database_path)
    return create_app(
        repository=repository,
        analysis_run_repository=repository,
        cloud_context=cloud_context,
        cors_origins=cors_origins,
    )


app = create_app()
