import type {
  AnalysisResponse,
  BlastRadiusResponse,
  CapabilitiesResponse,
  ClearWorkspaceResponse,
  DemoResetResponse,
  GraphResponse,
  GuidanceResponse,
  HealthResponse,
  IncidentDetail,
  IncidentSummary,
  MitreResponse,
  RiskResponse,
  S3AnalysisRequest,
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
  capabilities: (signal?: AbortSignal) =>
    getJson<CapabilitiesResponse>("/api/v1/capabilities", signal),
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
  analyzeFile: (payload: ArrayBuffer, contentType: string, sourceLabel?: string) =>
    postBytes<AnalysisResponse>(
      `/api/v1/analyses/file${sourceLabel ? `?source_label=${encodeURIComponent(sourceLabel)}` : ""}`,
      payload,
      contentType,
    ),
  analyzeS3: (request: S3AnalysisRequest) =>
    postJson<AnalysisResponse>("/api/v1/analyses/s3", request),
  resetDemo: () => postJson<DemoResetResponse>("/api/v1/demo/reset", {}),
  clearWorkspace: () =>
    postJson<ClearWorkspaceResponse>("/api/v1/workspace/clear", {}),
};

async function throwForStatus(response: Response): Promise<never> {
  let detail = `Request failed with status ${response.status}`;
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string" && body.detail.length > 0) {
      detail = body.detail;
    }
  } catch {
    // The status code remains the authoritative fallback for non-JSON failures.
  }
  throw new ApiError(detail, response.status);
}

async function postBytes<T>(
  path: string,
  payload: ArrayBuffer,
  contentType: string,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": contentType },
      body: payload,
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
    await throwForStatus(response);
  }
  return (await response.json()) as T;
}

async function postJson<T>(path: string, payload: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(payload),
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
    await throwForStatus(response);
  }
  return (await response.json()) as T;
}
