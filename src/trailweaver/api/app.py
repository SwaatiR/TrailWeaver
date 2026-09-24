"""FastAPI application factory for TrailWeaver investigation results."""

from fastapi import FastAPI, HTTPException

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
from trailweaver.cloud_context import CloudContext

_NO_CLOUD_CONTEXT_REASON = (
    "Blast-radius analysis is unavailable because no cloud context is loaded."
)


def create_app(
    *,
    repository: IncidentRepository | None = None,
    cloud_context: CloudContext | None = None,
    service: IncidentAnalysisService | None = None,
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
    application = FastAPI(title="TrailWeaver API", version="1.0.0")

    def incident_not_found(error: IncidentNotFoundError) -> HTTPException:
        return HTTPException(status_code=404, detail=f"Incident {error.args[0]!r} not found")

    @application.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
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


app = create_app()
