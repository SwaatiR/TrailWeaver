import type {
  BlastRadiusResponse,
  GraphResponse,
  GuidanceResponse,
  HealthResponse,
  IncidentDetail,
  IncidentSummary,
  MitreResponse,
  RiskResponse,
} from "../types/api";

const configuredBaseUrl = import.meta.env.VITE_TRAILWEAVER_API_URL?.trim();

export const apiBaseUrl = (configuredBaseUrl || "http://localhost:8000").replace(
  /\/$/,
  "",
);

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw error;
    }
    throw new ApiError(
      `Could not reach the TrailWeaver API at ${apiBaseUrl}. Check that the backend is running and this dashboard origin is allowed.`,
      0,
    );
  }

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // The status code remains the authoritative fallback for non-JSON failures.
    }
    throw new ApiError(detail, response.status);
  }

  return (await response.json()) as T;
}

function incidentPath(incidentId: string, suffix = ""): string {
  return `/api/v1/incidents/${encodeURIComponent(incidentId)}${suffix}`;
}

export const trailWeaverApi = {
  health: (signal?: AbortSignal) => getJson<HealthResponse>("/health", signal),
  listIncidents: (signal?: AbortSignal) =>
    getJson<IncidentSummary[]>("/api/v1/incidents", signal),
  getIncident: (incidentId: string, signal?: AbortSignal) =>
    getJson<IncidentDetail>(incidentPath(incidentId), signal),
  getRisk: (incidentId: string, signal?: AbortSignal) =>
    getJson<RiskResponse>(incidentPath(incidentId, "/risk"), signal),
  getMitre: (incidentId: string, signal?: AbortSignal) =>
    getJson<MitreResponse>(incidentPath(incidentId, "/mitre"), signal),
  getBlastRadius: (incidentId: string, signal?: AbortSignal) =>
    getJson<BlastRadiusResponse>(
      incidentPath(incidentId, "/blast-radius"),
      signal,
    ),
  getGraph: (incidentId: string, signal?: AbortSignal) =>
    getJson<GraphResponse>(incidentPath(incidentId, "/graph"), signal),
  getGuidance: (incidentId: string, signal?: AbortSignal) =>
    getJson<GuidanceResponse>(incidentPath(incidentId, "/guidance"), signal),
};
