import { useEffect, useId, useMemo, useRef, useState } from "react";
import { ApiError, trailWeaverApi } from "../api/client";
import { AttackGraphView } from "../components/AttackGraphView";
import { Icon, type IconName } from "../components/Icon";
import { PanelError, PanelSkeleton } from "../components/StatusViews";
import { orderTimelineEntries } from "../replay/attackReplay";
import type {
  AnalysisResponse,
  BlastRadiusResponse,
  CapabilitiesResponse,
  EvidenceProvenance,
  GraphResponse,
  GuidanceResponse,
  IncidentDetail,
  IncidentProvenance,
  IncidentSummary,
  MitreResponse,
  ObservingRun,
  Recommendation,
  RiskResponse,
} from "../types/api";

type Loadable<T> =
  | { status: "idle" | "loading" }
  | { status: "success"; data: T }
  | { status: "error"; message: string };

type BackendStatus = "checking" | "online" | "offline";

type LatestAnalysis = {
  source: "file" | "s3";
  result: AnalysisResponse;
};

const loading = <T,>(): Loadable<T> => ({ status: "loading" });
const idle = <T,>(): Loadable<T> => ({ status: "idle" });

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return "This incident is no longer available. Refresh the incident queue and choose another incident.";
    }
    return error.message;
  }
  return "The request could not be completed. Retry the analysis.";
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Time unavailable";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(date);
}

function timelineAnchorId(signalId: string): string {
  return `timeline-signal-${encodeURIComponent(signalId)}`;
}

function titleCase(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function actorLabel(incident: IncidentDetail): string {
  const actor = incident.primary_actor;
  return actor?.name ?? actor?.identifier ?? actor?.arn ?? "Actor unavailable";
}

function incidentDuration(incident: IncidentDetail): string {
  const start = new Date(incident.started_at).valueOf();
  const end = new Date(incident.ended_at).valueOf();
  if (Number.isNaN(start) || Number.isNaN(end)) return "Duration unavailable";
  const minutes = Math.max(0, Math.round((end - start) / 60_000));
  return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

function SeverityBadge({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  return (
    <span className={`severity-badge severity-badge--${normalized}`}>
      <span className="severity-badge__dot" aria-hidden="true" />
      {titleCase(value)}
    </span>
  );
}

function MetricCard({
  icon,
  label,
  value,
  detail,
  tone,
  loading: isLoading = false,
}: {
  icon: IconName;
  label: string;
  value: string;
  detail?: string;
  tone?: "critical" | "high" | "neutral";
  loading?: boolean;
}) {
  return (
    <article
      className={`metric-card ${tone ? `metric-card--${tone}` : ""}`}
      aria-busy={isLoading || undefined}
    >
      <span className="metric-card__icon"><Icon name={icon} /></span>
      <div>
        <p>{label}</p>
        {isLoading ? (
          <span className="metric-card__skeleton" aria-label={`${label} loading`} />
        ) : (
          <strong>{value}</strong>
        )}
      </div>
      {detail ? <span className="metric-card__detail">{detail}</span> : null}
    </article>
  );
}

function PanelHeading({
  id,
  title,
  description,
  level = "h2",
}: {
  id: string;
  title: string;
  description: string;
  level?: "h2" | "h3";
}) {
  const Heading = level;
  return (
    <div className="panel-heading">
      <div>
        <Heading id={id}>{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

function SectionHeading({
  id,
  title,
  description,
}: {
  id: string;
  title: string;
  description: string;
}) {
  return (
    <header className="section-heading">
      <h2 id={id}>{title}</h2>
      <p>{description}</p>
    </header>
  );
}

function GuidanceItem({ item, order }: { item: Recommendation; order: number }) {
  return (
    <article className="guidance-item">
      <span className="guidance-item__number" aria-label={`Recommendation ${order}`}>
        {order}
      </span>
      <div className="guidance-item__body">
        <div className="guidance-item__title-row">
          <h3>{item.title}</h3>
          <span className={`priority priority--${item.priority.toLowerCase()}`}>
            {titleCase(item.priority)}
          </span>
        </div>
        <p>{item.description}</p>
        <p className="guidance-item__rationale">
          <strong>Why:</strong> {item.rationale}
        </p>
      </div>
    </article>
  );
}

function shortenSourceLabel(label: string | null): string {
  // Compact display only: the expanded details always show the complete
  // persisted label. Middle-truncation keeps S3 bucket roots and file
  // tails recognizable without reconstructing any path.
  if (label === null) return "No source label";
  const limit = 34;
  if (label.length <= limit) return label;
  return `${label.slice(0, 20)}…${label.slice(-12)}`;
}

function runStatusLabel(status: string): string {
  const normalized = status.toLowerCase();
  if (normalized === "completed") return "Completed";
  if (normalized === "running") return "Running";
  if (normalized === "failed") return "Failed";
  return titleCase(status);
}

function ProvenanceRunDetails({ run }: { run: ObservingRun }) {
  const statusClass = `provenance-status provenance-status--${run.status.toLowerCase()}`;
  // An interrupted run's timestamp marks durable classification, not the
  // moment execution ended — label it truthfully.
  const terminalTimeLabel =
    run.status.toLowerCase() === "interrupted" ? "Classified interrupted" : "Finished";
  return (
    <div className="provenance-run">
      <code className="provenance-run__id">{run.analysis_run_id}</code>
      <dl className="provenance-run__facts">
        <div>
          <dt>Source type</dt>
          <dd>{titleCase(run.source_type)}</dd>
        </div>
        <div className="provenance-run__label-row">
          <dt>Source label</dt>
          <dd>{run.source_label ?? "No source label"}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd><span className={statusClass}>{runStatusLabel(run.status)}</span></dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd><time dateTime={run.started_at}>{formatDateTime(run.started_at)}</time></dd>
        </div>
        <div>
          <dt>{terminalTimeLabel}</dt>
          <dd>
            {run.finished_at ? (
              <time dateTime={run.finished_at}>{formatDateTime(run.finished_at)}</time>
            ) : (
              "Still running"
            )}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function EvidenceProvenanceItem({
  item,
  runsById,
}: {
  item: EvidenceProvenance;
  runsById: Map<string, ObservingRun>;
}) {
  const knownRuns = item.observed_run_ids.filter((runId) => runsById.has(runId));
  const missingRuns = item.observed_run_ids.filter((runId) => !runsById.has(runId));
  const [firstRunId, ...additionalRunIds] = knownRuns;
  const firstRun = firstRunId ? runsById.get(firstRunId) : undefined;
  const runCount = item.observed_run_ids.length;

  return (
    <li className="provenance-evidence">
      <div className="provenance-evidence__head">
        <strong>{item.title}</strong>
        <span className="rule-chip">{item.rule_id}</span>
      </div>
      <dl className="provenance-evidence__facts">
        <div>
          <dt>Provider event ID</dt>
          <dd>{item.event_id ?? "No provider event ID"}</dd>
        </div>
        <div>
          <dt>Event time</dt>
          <dd><time dateTime={item.event_time}>{formatDateTime(item.event_time)}</time></dd>
        </div>
        <div>
          <dt>First recorded by TrailWeaver</dt>
          <dd>
            {item.first_recorded_at ? (
              <time dateTime={item.first_recorded_at}>
                {formatDateTime(item.first_recorded_at)}
              </time>
            ) : (
              "Not recorded"
            )}
          </dd>
        </div>
      </dl>
      {item.observation_state === "recorded" ? (
        <p className="provenance-evidence__state">
          Observed in {runCount} recorded run{runCount === 1 ? "" : "s"}.
        </p>
      ) : null}
      {item.observation_state === "history_unavailable" ? (
        <p className="provenance-evidence__state provenance-evidence__state--unavailable">
          Recorded run history is unavailable for this evidence.
        </p>
      ) : null}
      {item.observation_state === "identity_unavailable" ? (
        <p className="provenance-evidence__state provenance-evidence__state--unavailable">
          Run history is unavailable because this evidence has no provider event ID.
        </p>
      ) : null}
      {firstRun ? <ProvenanceRunDetails run={firstRun} /> : null}
      {additionalRunIds.length > 0 ? (
        <details className="provenance-additional">
          <summary>
            +{additionalRunIds.length} additional observation
            {additionalRunIds.length === 1 ? "" : "s"}
          </summary>
          {additionalRunIds.map((runId) => {
            const run = runsById.get(runId);
            return run ? <ProvenanceRunDetails key={runId} run={run} /> : null;
          })}
        </details>
      ) : null}
      {missingRuns.map((runId) => (
        <p key={runId} className="provenance-evidence__state provenance-evidence__state--unavailable">
          Recorded observation <code>{runId}</code> has no stored run record.
        </p>
      ))}
    </li>
  );
}

export function EvidenceProvenancePanel({
  provenance,
  onRetry,
}: {
  provenance: Loadable<IncidentProvenance>;
  onRetry: () => void;
}) {
  if (provenance.status === "error") {
    return (
      <div className="analysis-panel provenance-panel">
        <PanelHeading
          id="provenance-title"
          title="Evidence provenance"
          description="Where this incident's evidence was recorded."
          level="h3"
        />
        <PanelError
          title="Evidence provenance unavailable"
          message={provenance.message}
          onRetry={onRetry}
        />
      </div>
    );
  }
  if (provenance.status !== "success") {
    return (
      <div className="analysis-panel provenance-panel" aria-busy="true">
        <PanelHeading
          id="provenance-title"
          title="Evidence provenance"
          description="Where this incident's evidence was recorded."
          level="h3"
        />
        <PanelSkeleton rows={3} />
      </div>
    );
  }
  const data = provenance.data;
  const summary = data.summary;
  const runsById = new Map(data.observing_runs.map((run) => [run.analysis_run_id, run]));
  const labels = data.observing_runs.slice(0, 3);
  const partialCoverage =
    summary.identified_event_count > 0 &&
    summary.identified_events_with_recorded_observations < summary.identified_event_count;
  const eventRange =
    summary.event_time_start && summary.event_time_end
      ? `${formatDateTime(summary.event_time_start)} – ${formatDateTime(summary.event_time_end)}`
      : "Event time unavailable";

  return (
    <div className="analysis-panel provenance-panel">
      <PanelHeading
        id="provenance-title"
        title="Evidence provenance"
        description="Recorded analysis runs that observed this incident's evidence. TrailWeaver shows where evidence was recorded — never which run created the incident."
        level="h3"
      />
      <dl className="provenance-summary" aria-label="Recorded provenance summary">
        <div>
          <dt>Evidence signals</dt>
          <dd>{summary.evidence_signal_count}</dd>
        </div>
        <div>
          <dt>Identified events with recorded observations</dt>
          <dd>
            {summary.identified_events_with_recorded_observations} of{" "}
            {summary.identified_event_count}
          </dd>
        </div>
        <div>
          <dt>Observing runs</dt>
          <dd>{summary.observing_run_count}</dd>
        </div>
        <div>
          <dt>Event time</dt>
          <dd>{eventRange}</dd>
        </div>
      </dl>
      {summary.source_types.length > 0 ? (
        <ul className="tag-chips provenance-chips" aria-label="Observing run source types">
          {summary.source_types.map((sourceType) => (
            <li key={sourceType}>{titleCase(sourceType)}</li>
          ))}
        </ul>
      ) : null}
      {labels.length > 0 ? (
        <ul className="provenance-labels" aria-label="Observing run sources">
          {labels.map((run) => (
            <li key={run.analysis_run_id} title={run.source_label ?? undefined}>
              {shortenSourceLabel(run.source_label)}
            </li>
          ))}
        </ul>
      ) : null}
      {partialCoverage ? (
        <p className="provenance-notice" role="note">
          Recorded run history is available for{" "}
          {summary.identified_events_with_recorded_observations} of{" "}
          {summary.identified_event_count} identified events.
        </p>
      ) : null}
      <details className="provenance-details">
        <summary>View event-to-run details</summary>
        <ol className="provenance-evidence-list">
          {data.evidence.map((item) => (
            <EvidenceProvenanceItem key={item.signal_id} item={item} runsById={runsById} />
          ))}
        </ol>
      </details>
    </div>
  );
}

const WORKFLOW_STEPS = [
  { name: "CloudTrail evidence", detail: "AWS API records" },
  { name: "Ingestion", detail: "Normalize exports" },
  { name: "Detection", detail: "Suspicious behavior" },
  { name: "Signals", detail: "Observed findings" },
  { name: "Correlation", detail: "Related activity" },
  { name: "Incidents", detail: "Correlated cases" },
  { name: "Investigation", detail: "Timeline and context" },
] as const;

type Route = "overview" | "incidents" | "history" | "investigation" | "graph";

const ROUTE_HASHES: Record<Route, string> = {
  overview: "#/overview",
  incidents: "#/incidents",
  history: "#/history",
  investigation: "#/investigation",
  graph: "#/investigation/graph",
};

const ROUTE_STORAGE_KEY = "trailweaver.route.v1";
const WELCOME_STORAGE_KEY = "trailweaver.welcome.v1";
const HISTORY_CLEARED_STORAGE_KEY = "trailweaver.historyClearedAt.v1";

function parseRouteHash(hash: string): Route | null {
  if (hash === ROUTE_HASHES.overview) return "overview";
  if (hash === ROUTE_HASHES.incidents) return "incidents";
  if (hash === ROUTE_HASHES.history) return "history";
  if (hash === ROUTE_HASHES.investigation) return "investigation";
  if (hash === ROUTE_HASHES.graph) return "graph";
  return null;
}

function readStoredRoute(): Route | null {
  try {
    const stored = window.sessionStorage.getItem(ROUTE_STORAGE_KEY);
    if (
      stored === "overview" ||
      stored === "incidents" ||
      stored === "history" ||
      stored === "investigation" ||
      stored === "graph"
    ) {
      return stored;
    }
  } catch {
    // Storage is unavailable; fall back to the default route.
  }
  return null;
}

function readHistoryClearedAt(): string | null {
  try {
    const stored = window.sessionStorage.getItem(HISTORY_CLEARED_STORAGE_KEY);
    if (stored && !Number.isNaN(Date.parse(stored))) return stored;
  } catch {
    // Storage is unavailable; no dismissal watermark applies.
  }
  return null;
}

function isRecentInvestigation(createdAt: string, clearedAt: string | null): boolean {
  // Rolling 24-hour display window only: older investigations stay persisted
  // and simply fall outside this view. Nothing is ever deleted here.
  const created = Date.parse(createdAt);
  if (Number.isNaN(created)) return false;
  const now = Date.now();
  // A small future tolerance covers backend/browser clock skew so a
  // just-created investigation never flickers out of view.
  if (created < now - 24 * 60 * 60 * 1000 || created > now + 60 * 1000) return false;
  if (clearedAt !== null && created <= Date.parse(clearedAt)) return false;
  return true;
}

function isWelcomeDismissed(): boolean {
  try {
    return window.localStorage.getItem(WELCOME_STORAGE_KEY) === "dismissed";
  } catch {
    return true;
  }
}

function scrollToPanel(targetId: string): void {
  // In-page scroll that deliberately leaves location.hash alone: the hash
  // is the route, so section navigation must not write competing anchors.
  // All investigation section IDs use the inv- prefix so they can never be
  // mistaken for an application route (routes always contain a slash).
  const target = document.getElementById(targetId);
  if (!target) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  target.scrollIntoView({
    behavior: reduced ? "auto" : "smooth",
    block: "start",
  });
  target.focus({ preventScroll: true });
}

const INVESTIGATION_SECTIONS = {
  overview: "inv-overview",
  timeline: "inv-timeline",
  provenance: "inv-provenance",
  analysis: "inv-analysis",
  reconstruction: "inv-reconstruction",
  blast: "inv-blast",
  guidance: "inv-guidance",
} as const;

function scrollToInvestigationSection(targetId: string): void {
  scrollToPanel(targetId);
}

function WorkflowStrip() {
  return (
    <ol
      className="workflow-strip"
      aria-label="Product workflow: CloudTrail, detection, correlation, incident, investigation"
    >
      {WORKFLOW_STEPS.map((step) => (
        <li key={step.name}>
          <strong>{step.name}</strong>
          <span>{step.detail}</span>
        </li>
      ))}
    </ol>
  );
}

function EvidenceWeave() {
  return (
    <figure className="evidence-weave">
      <figcaption className="visually-hidden">
        Multiple CloudTrail activities pass through detection and correlation
        to become one explainable investigation.
      </figcaption>
      <div className="evidence-weave__meta" aria-hidden="true">
        <span>CloudTrail activity</span>
        <span>Correlated outcome</span>
      </div>
      <div className="evidence-weave__canvas" aria-hidden="true">
        <svg
          className="evidence-weave__paths"
          viewBox="0 0 640 340"
          preserveAspectRatio="none"
        >
          <path d="M104 55 C210 55 222 125 318 125 S430 170 516 170" />
          <path d="M104 170 C216 170 246 170 318 170 S430 170 516 170" />
          <path d="M104 285 C210 285 222 215 318 215 S430 170 516 170" />
          <circle cx="318" cy="125" r="4" />
          <circle cx="318" cy="170" r="4" />
          <circle cx="318" cy="215" r="4" />
          <circle cx="516" cy="170" r="5" />
        </svg>

        <div className="evidence-node evidence-node--one">
          <Icon name="cloud" />
          <span><strong>Identity event</strong>CloudTrail record</span>
        </div>
        <div className="evidence-node evidence-node--two">
          <Icon name="key" />
          <span><strong>Credential event</strong>CloudTrail record</span>
        </div>
        <div className="evidence-node evidence-node--three">
          <Icon name="shield" />
          <span><strong>Policy event</strong>CloudTrail record</span>
        </div>

        <div className="weave-stage weave-stage--detect">Detection</div>
        <div className="weave-stage weave-stage--signals">Signals</div>
        <div className="weave-stage weave-stage--correlate">Correlation</div>

        <div className="weave-outcome">
          <span className="weave-outcome__icon"><Icon name="incident" /></span>
          <p>One investigation</p>
          <strong>Evidence connected in context</strong>
          <ul>
            <li>Observed timeline</li>
            <li>Explainable risk</li>
            <li>ATT&amp;CK mapping</li>
          </ul>
        </div>
      </div>
      <div className="evidence-weave__legend" aria-hidden="true">
        <span><i />Observed evidence</span>
        <span><i />Interpreted relationship</span>
      </div>
    </figure>
  );
}

function OverviewHero({
  populated = false,
  onOpenInvestigation,
}: {
  populated?: boolean;
  onOpenInvestigation?: () => void;
}) {
  return (
    <section
      className={`overview-command ${populated ? "overview-command--populated" : ""}`}
      aria-labelledby="overview-title"
    >
      <div className="overview-command__copy">
        <div className="overview-wordmark" aria-label="TrailWeaver">
          <span aria-hidden="true">TW</span>
          <strong>TRAILWEAVER</strong>
        </div>
        <h1 id="overview-title">
          CloudTrail evidence, woven into an investigation.
        </h1>
        <p>
          Detect suspicious AWS activity, connect related signals, and
          reconstruct explainable incidents for investigation.
        </p>
        <div className="overview-command__actions">
          {populated ? (
            <button type="button" onClick={onOpenInvestigation}>
              Open featured investigation
              <Icon name="arrow" />
            </button>
          ) : (
            <>
              <button type="button" onClick={() => scrollToPanel("analyze-file")}>
                Analyze CloudTrail
                <Icon name="arrow" />
              </button>
              <button
                type="button"
                className="overview-command__secondary"
                onClick={() => scrollToPanel("analyze-s3")}
              >
                Analyze from AWS S3
              </button>
            </>
          )}
        </div>
      </div>
      <EvidenceWeave />
    </section>
  );
}

function WelcomeCard() {
  const [dismissed, setDismissed] = useState<boolean>(() => isWelcomeDismissed());

  if (dismissed) return null;

  const dismiss = () => {
    try {
      window.localStorage.setItem(WELCOME_STORAGE_KEY, "dismissed");
    } catch {
      // Dismissal is best-effort when storage is unavailable.
    }
    setDismissed(true);
  };

  return (
    <section className="welcome-card" aria-labelledby="welcome-title">
      <div>
        <p className="welcome-card__kicker">First time here</p>
        <h2 id="welcome-title">From CloudTrail evidence to investigation</h2>
        <ol>
          <li>
            <strong>Evidence in.</strong> TrailWeaver analyzes AWS CloudTrail
            exports — a file upload or an explicit S3 object.
          </li>
          <li>
            <strong>Correlated cases.</strong> Detections become signals,
            related signals become incidents in the queue.
          </li>
          <li>
            <strong>Investigate.</strong> Open the featured investigation above
            for its timeline, risk, ATT&amp;CK, graph, replay, and guidance.
          </li>
        </ol>
      </div>
      <button type="button" onClick={dismiss}>
        Dismiss welcome
      </button>
    </section>
  );
}

const MAX_SHOWN_DIAGNOSTICS = 20;

export function AnalysisCompletePanel({
  result,
  sourceKind,
  queueCount,
  analyzeAnotherLabel,
  onOpenInvestigation,
  onAnalyzeAnother,
}: {
  result: AnalysisResponse;
  sourceKind: "file" | "s3";
  queueCount: number;
  analyzeAnotherLabel: string;
  onOpenInvestigation: (incidentId: string) => void;
  onAnalyzeAnother: () => void;
}) {
  const headingId = useId();
  const panelRef = useRef<HTMLElement>(null);
  const incidentCount = result.incident_ids.length;
  const hasIncidents = incidentCount > 0;
  const hasSignalsWithoutIncident = !hasIncidents && result.signals > 0;
  const shownIssues = result.issues.slice(0, MAX_SHOWN_DIAGNOSTICS);
  const hiddenIssueCount = result.issues.length - shownIssues.length;
  const showDiagnostics =
    result.failed_records > 0 ||
    result.duplicate_records > 0 ||
    result.issues.length > 0 ||
    result.persisted_incidents !== result.incidents_created;

  useEffect(() => {
    const node = panelRef.current;
    if (!node) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    node.focus({ preventScroll: true });
    node.scrollIntoView({
      behavior: reduced ? "auto" : "smooth",
      block: "nearest",
    });
  }, []);

  const sourceFallback = sourceKind === "file" ? "Uploaded file" : "S3 object";

  return (
    <section
      ref={panelRef}
      className="analysis-complete"
      aria-labelledby={headingId}
      tabIndex={-1}
    >
      <p className="analysis-complete__kicker">
        <span aria-hidden="true" />
        Result of this analysis
      </p>
      <h4 id={headingId} className="analysis-complete__title">
        Analysis complete
      </h4>
      <p className="analysis-complete__source">
        CloudTrail evidence processed successfully. Source:{" "}
        {result.source_label ?? sourceFallback}
      </p>

      <dl className="analysis-complete__metrics" aria-label="What this analysis produced">
        <div className="analysis-complete__metric">
          <dt>Records processed</dt>
          <dd>{result.total_records}</dd>
        </div>
        <div className="analysis-complete__metric">
          <dt>Events accepted</dt>
          <dd>{result.accepted_records}</dd>
        </div>
        <div className="analysis-complete__metric">
          <dt>Signals detected</dt>
          <dd>
            {result.signals}
            <span className="analysis-complete__metric-sub">
              {result.correlations}{" "}
              {result.correlations === 1 ? "correlation" : "correlations"}
            </span>
          </dd>
        </div>
        <div className="analysis-complete__metric">
          <dt>Incidents created</dt>
          <dd>
            {result.incidents_created}
            <span className="analysis-complete__metric-sub">by this analysis</span>
          </dd>
        </div>
      </dl>

      {hasIncidents ? (
        <div className="analysis-complete__outcome analysis-complete__outcome--incidents">
          <p>
            <strong>
              {result.incidents_created === 1
                ? "1 correlated incident created by this analysis."
                : `${result.incidents_created} correlated incidents created by this analysis.`}
            </strong>
          </p>
          {incidentCount === 1 ? (
            <p>
              The incident below is the one this analysis just created. Open
              it to investigate.
            </p>
          ) : (
            <p>
              Each entry below is an incident this analysis just created.
              Open any of them to investigate; the first one is the primary
              action.
            </p>
          )}
          {incidentCount === 1 ? (
            <div className="analysis-complete__actions">
              <button
                className="retry-button"
                type="button"
                onClick={() => {
                  const first = result.incident_ids[0];
                  if (first) onOpenInvestigation(first);
                }}
              >
                Open investigation
              </button>
              <button
                className="analysis-complete__secondary"
                type="button"
                onClick={onAnalyzeAnother}
              >
                {analyzeAnotherLabel}
              </button>
            </div>
          ) : (
            <>
              <div className="analysis-complete__actions">
                <button
                  className="retry-button"
                  type="button"
                  onClick={() => {
                    const first = result.incident_ids[0];
                    if (first) onOpenInvestigation(first);
                  }}
                >
                  Open first investigation
                </button>
                <button
                  className="analysis-complete__secondary"
                  type="button"
                  onClick={onAnalyzeAnother}
                >
                  {analyzeAnotherLabel}
                </button>
              </div>
              <ul className="analysis-complete__incident-list">
                {result.incident_ids.map((incidentId, index) => (
                  <li key={incidentId}>
                    <button type="button" onClick={() => onOpenInvestigation(incidentId)}>
                      Open investigation {index + 1}
                    </button>
                    <code>{incidentId}</code>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      ) : null}

      {hasSignalsWithoutIncident ? (
        <div className="analysis-complete__outcome analysis-complete__outcome--signals">
          <p>
            <strong>
              {result.signals === 1
                ? "1 suspicious signal detected — no correlated incident formed."
                : `${result.signals} suspicious signals detected — no correlated incident formed.`}
            </strong>
          </p>
          <p>
            This activity matched a detection rule, but the signals did not
            form a supported correlated incident. Signals are observed
            findings; incidents are correlated cases built from related
            signals. This is not a statement that the AWS account is safe.
          </p>
          <div className="analysis-complete__actions">
            <button
              className="retry-button"
              type="button"
              onClick={onAnalyzeAnother}
            >
              {analyzeAnotherLabel}
            </button>
          </div>
        </div>
      ) : null}

      {!hasIncidents && !hasSignalsWithoutIncident ? (
        <div className="analysis-complete__outcome analysis-complete__outcome--quiet">
          <p>
            <strong>
              No supported suspicious activity was detected in this analysis.
            </strong>
          </p>
          <p>
            TrailWeaver did not identify activity matching its current
            detection and correlation coverage. This is not a statement that
            the AWS account is safe.
          </p>
          <div className="analysis-complete__actions">
            <button
              className="retry-button"
              type="button"
              onClick={onAnalyzeAnother}
            >
              {analyzeAnotherLabel}
            </button>
          </div>
        </div>
      ) : null}

      {showDiagnostics ? (
        <div className="analysis-complete__diagnostics">
          <p>
            Processing notes: {result.accepted_records} of{" "}
            {result.total_records} accepted
            {result.failed_records > 0
              ? `, ${result.failed_records} rejected`
              : ""}
            {result.duplicate_records > 0
              ? `, ${result.duplicate_records} duplicate${result.duplicate_records === 1 ? "" : "s"} skipped`
              : ""}
            .
          </p>
          {result.persisted_incidents !== result.incidents_created ? (
            <p>
              {result.persisted_incidents} of {result.incidents_created}{" "}
              created incidents were persisted.
            </p>
          ) : null}
          {result.issues.length > 0 ? (
            <details>
              <summary>
                View {result.issues.length} record diagnostic
                {result.issues.length === 1 ? "" : "s"}
              </summary>
              <ul>
                {shownIssues.map((issue) => (
                  <li key={`${issue.record_index}-${issue.code}`}>
                    <span>Record {issue.record_index}</span>
                    <code>{issue.code}</code>
                    {issue.event_id ? <span>{issue.event_id}</span> : null}
                  </li>
                ))}
              </ul>
              {hiddenIssueCount > 0 ? (
                <p>
                  +{hiddenIssueCount} further diagnostic
                  {hiddenIssueCount === 1 ? "" : "s"} not shown.
                </p>
              ) : null}
            </details>
          ) : null}
        </div>
      ) : null}

      {queueCount > 0 ? (
        <p className="analysis-complete__queue-note">
          The incident queue is workspace state and may already list earlier
          incidents. Only the counts above were created by this analysis.
        </p>
      ) : null}

      <p className="analysis-complete__note">
        Reanalysis creates a new analysis run. Previously recorded event
        identities are deduplicated, so identified replay does not create
        duplicate incidents — while evidence without an event ID may be
        processed again.
      </p>
    </section>
  );
}

function FileAnalysisCard({
  available,
  unavailableReason,
  queueCount,
  analysis,
  onSuccess,
  onClear,
  resetToken,
  onOpenInvestigation,
}: {
  available: boolean;
  unavailableReason: string | null;
  queueCount: number;
  analysis: AnalysisResponse | null;
  onSuccess: (result: AnalysisResponse) => void;
  onClear: () => void;
  resetToken: number;
  onOpenInvestigation: (incidentId: string) => void;
}) {
  const [fileName, setFileName] = useState<string | null>(null);
  const [payload, setPayload] = useState<ArrayBuffer | null>(null);
  const [contentType, setContentType] = useState("application/json");
  const [fileError, setFileError] = useState<string | null>(null);
  const [state, setState] = useState<Loadable<AnalysisResponse>>(idle());
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Scanner reset (e.g. closing an investigation): return the file
    // scanner to its initial state. Runs harmlessly on mount, when every
    // field already holds its initial value.
    setFileName(null);
    setPayload(null);
    setFileError(null);
    setState(idle());
    if (inputRef.current) inputRef.current.value = "";
  }, [resetToken]);

  const resetInputValue = () => {
    // Browsers only emit change when the selection differs, so the native
    // value must be cleared for the same file to be choosable again.
    if (inputRef.current) inputRef.current.value = "";
  };

  const removeFile = () => {
    // Local scanner state only: no backend call, no incident or storage
    // impact, and the original file on disk is never touched.
    setFileName(null);
    setPayload(null);
    resetInputValue();
    inputRef.current?.focus();
  };

  const chooseFile = (file: File | undefined) => {
    setFileError(null);
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setFileName(null);
      setPayload(null);
      setFileError("This file exceeds the 10 MiB upload limit.");
      resetInputValue();
      return;
    }
    const allowed = ["application/json", "application/gzip", "application/x-gzip"];
    setContentType(
      allowed.includes(file.type) ? file.type : "application/octet-stream",
    );
    void file.arrayBuffer().then(
      (buffer) => {
        setFileName(file.name);
        setPayload(buffer);
      },
      () => {
        setFileName(null);
        setPayload(null);
        setFileError("This file could not be read by the browser.");
      },
    );
  };

  const analyze = () => {
    if (!payload) return;
    setState(loading());
    trailWeaverApi
      .analyzeFile(payload, contentType, fileName ?? undefined)
      .then((result) => {
        setState(idle());
        onSuccess(result);
      })
      .catch((error: unknown) => {
        setState({ status: "error", message: errorMessage(error) });
      });
  };

  const analyzeAnother = () => {
    onClear();
    setState(idle());
    setFileName(null);
    setPayload(null);
    resetInputValue();
    requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
  };

  return (
    <article
      id="analyze-file"
      className="get-started-card"
      aria-labelledby="get-started-file-title"
      tabIndex={-1}
    >
      <h3 id="get-started-file-title">CloudTrail file</h3>
      <p>Analyze a CloudTrail JSON or gzipped JSON export.</p>
      {analysis ? (
        <AnalysisCompletePanel
          result={analysis}
          sourceKind="file"
          queueCount={queueCount}
          analyzeAnotherLabel="Scan another file"
          onOpenInvestigation={onOpenInvestigation}
          onAnalyzeAnother={analyzeAnother}
        />
      ) : !available ? (
        <p className="get-started-card__unavailable">
          {unavailableReason ?? "File analysis is unavailable on this API instance."}
        </p>
      ) : (
        <>
          <label className="field-label" htmlFor="cloudtrail-file-input">
            Evidence file (JSON or .gz, up to 10 MiB)
          </label>
          <input
            id="cloudtrail-file-input"
            ref={inputRef}
            className="file-input"
            type="file"
            accept=".json,.gz,application/json,application/gzip"
            onChange={(event) => chooseFile(event.target.files?.[0])}
          />
          {fileName ? (
            <p className="field-hint selected-file-row">
              <span>Selected: {fileName}</span>
              <button
                type="button"
                className="selected-file-remove"
                aria-label="Remove selected file"
                onClick={removeFile}
              >
                Remove
              </button>
            </p>
          ) : null}
          {fileError ? (
            <p className="field-error" role="alert">{fileError}</p>
          ) : null}
          {state.status === "error" ? (
            <p className="field-error" role="alert">{state.message}</p>
          ) : null}
          <button
            className="retry-button"
            type="button"
            disabled={!payload || state.status === "loading"}
            onClick={analyze}
          >
            {state.status === "loading" ? "Analyzing…" : "Analyze file"}
          </button>
        </>
      )}
    </article>
  );
}

function S3AnalysisCard({
  available,
  unavailableReason,
  queueCount,
  analysis,
  onSuccess,
  onClear,
  onOpenInvestigation,
}: {
  available: boolean;
  unavailableReason: string | null;
  queueCount: number;
  analysis: AnalysisResponse | null;
  onSuccess: (result: AnalysisResponse) => void;
  onClear: () => void;
  onOpenInvestigation: (incidentId: string) => void;
}) {
  const [bucket, setBucket] = useState("");
  const [key, setKey] = useState("");
  const [region, setRegion] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [state, setState] = useState<Loadable<AnalysisResponse>>(idle());

  const analyze = () => {
    setFormError(null);
    if (!bucket.trim() || !key.trim()) {
      setFormError("Bucket and object key are both required.");
      return;
    }
    setState(loading());
    trailWeaverApi
      .analyzeS3({
        bucket: bucket.trim(),
        key: key.trim(),
        ...(region.trim() ? { region: region.trim() } : {}),
      })
      .then((result) => {
        setState(idle());
        onSuccess(result);
      })
      .catch((error: unknown) => {
        setState({ status: "error", message: errorMessage(error) });
      });
  };

  const analyzeAnother = () => {
    onClear();
    setState(idle());
    requestAnimationFrame(() => {
      document.getElementById("s3-bucket-input")?.focus();
    });
  };

  return (
    <article
      id="analyze-s3"
      className="get-started-card"
      aria-labelledby="get-started-s3-title"
      tabIndex={-1}
    >
      <h3 id="get-started-s3-title">AWS S3</h3>
      <p>Analyze an explicit CloudTrail object with the backend&apos;s identity.</p>
      {analysis ? (
        <AnalysisCompletePanel
          result={analysis}
          sourceKind="s3"
          queueCount={queueCount}
          analyzeAnotherLabel="Analyze another object"
          onOpenInvestigation={onOpenInvestigation}
          onAnalyzeAnother={analyzeAnother}
        />
      ) : !available ? (
        <p className="get-started-card__unavailable">
          {unavailableReason ?? "S3 analysis is unavailable on this API instance."}
        </p>
      ) : (
        <>
          <label className="field-label" htmlFor="s3-bucket-input">Bucket</label>
          <input
            id="s3-bucket-input"
            className="field-input"
            type="text"
            autoComplete="off"
            placeholder="example-cloudtrail-bucket"
            value={bucket}
            onChange={(event) => setBucket(event.target.value)}
          />
          <label className="field-label" htmlFor="s3-key-input">Object key</label>
          <input
            id="s3-key-input"
            className="field-input"
            type="text"
            autoComplete="off"
            placeholder="AWSLogs/111122223333/CloudTrail/us-east-1/export.json.gz"
            value={key}
            onChange={(event) => setKey(event.target.value)}
          />
          <label className="field-label" htmlFor="s3-region-input">
            Region <span className="field-optional">(optional)</span>
          </label>
          <input
            id="s3-region-input"
            className="field-input"
            type="text"
            autoComplete="off"
            placeholder="us-east-1"
            value={region}
            onChange={(event) => setRegion(event.target.value)}
          />
          <p className="field-hint">
            Uses the backend&apos;s AWS identity — an instance profile,
            environment credentials, or container role. TrailWeaver never asks
            for access keys.
          </p>
          {formError ? (
            <p className="field-error" role="alert">{formError}</p>
          ) : null}
          {state.status === "error" ? (
            <p className="field-error" role="alert">{state.message}</p>
          ) : null}
          <button
            className="retry-button"
            type="button"
            disabled={state.status === "loading"}
            onClick={analyze}
          >
            {state.status === "loading" ? "Analyzing…" : "Analyze S3 object"}
          </button>
        </>
      )}
    </article>
  );
}

function GetStartedPanels({
  capabilities,
  queueCount,
  latestAnalysis,
  scannerResetToken,
  onAnalysisComplete,
  onClearAnalysis,
  onDemoReset,
  onOpenInvestigation,
}: {
  capabilities: Loadable<CapabilitiesResponse>;
  queueCount: number;
  latestAnalysis: LatestAnalysis | null;
  scannerResetToken: number;
  onAnalysisComplete: (result: AnalysisResponse, source: "file" | "s3") => void;
  onClearAnalysis: () => void;
  onDemoReset: () => void;
  onOpenInvestigation: (incidentId: string) => void;
}) {
  const fileAvailable =
    capabilities.status === "success" && capabilities.data.file_analysis;
  const s3Available =
    capabilities.status === "success" && capabilities.data.s3_analysis;
  const demoMode =
    capabilities.status === "success" && capabilities.data.demo_mode;
  const pendingReason =
    capabilities.status === "loading" || capabilities.status === "idle"
      ? "Checking availability…"
      : capabilities.status === "error"
        ? `Availability could not be confirmed: ${capabilities.message}`
        : null;
  const s3UnavailableReason =
    !s3Available && demoMode
      ? "S3 analysis is unavailable in the local demo."
      : pendingReason;
  const [resetState, setResetState] = useState<Loadable<never>>(idle());

  const resetDemo = () => {
    setResetState(loading());
    trailWeaverApi
      .resetDemo()
      .then(() => {
        setResetState(idle());
        onDemoReset();
      })
      .catch((error: unknown) => {
        setResetState({ status: "error", message: errorMessage(error) });
      });
  };

  return (
    <section className="get-started" aria-labelledby="get-started-title">
      <h2 id="get-started-title">Start an investigation</h2>
      <p>
        Supply CloudTrail evidence to analyze. Persisted incidents appear in
        the incident queue and the Incidents list — open any incident to
        investigate it.
      </p>
      <div className="get-started-grid">
        <FileAnalysisCard
          available={fileAvailable}
          unavailableReason={pendingReason}
          queueCount={queueCount}
          analysis={latestAnalysis?.source === "file" ? latestAnalysis.result : null}
          onSuccess={(result) => onAnalysisComplete(result, "file")}
          onClear={onClearAnalysis}
          resetToken={scannerResetToken}
          onOpenInvestigation={onOpenInvestigation}
        />
        <S3AnalysisCard
          available={s3Available}
          unavailableReason={s3UnavailableReason}
          queueCount={queueCount}
          analysis={latestAnalysis?.source === "s3" ? latestAnalysis.result : null}
          onSuccess={(result) => onAnalysisComplete(result, "s3")}
          onClear={onClearAnalysis}
          onOpenInvestigation={onOpenInvestigation}
        />
      </div>
      {demoMode ? (
        <div className="demo-reset">
          <button
            className="analysis-complete__secondary"
            type="button"
            disabled={resetState.status === "loading"}
            onClick={resetDemo}
          >
            {resetState.status === "loading" ? "Resetting…" : "Reset demo"}
          </button>
          <span>
            Clears the local demo workspace so the fixture can be analyzed again.
          </span>
          {resetState.status === "error" ? (
            <p className="field-error" role="alert">{resetState.message}</p>
          ) : null}
        </div>
      ) : null}
      <p
        className="workflow-short"
        aria-label="Short product workflow: CloudTrail, detection, correlation, incident, investigation"
      >
        CloudTrail → Detection → Correlation → Incident → Investigation
      </p>
    </section>
  );
}

function ZeroIncidentPanel({
  capabilities,
  latestAnalysis,
  scannerResetToken,
  onAnalysisComplete,
  onClearAnalysis,
  onDemoReset,
  onOpenInvestigation,
}: {
  capabilities: Loadable<CapabilitiesResponse>;
  latestAnalysis: LatestAnalysis | null;
  scannerResetToken: number;
  onAnalysisComplete: (result: AnalysisResponse, source: "file" | "s3") => void;
  onClearAnalysis: () => void;
  onDemoReset: () => void;
  onOpenInvestigation: (incidentId: string) => void;
}) {
  const workspaceReady =
    capabilities.status === "success" &&
    (capabilities.data.file_analysis || capabilities.data.s3_analysis);
  const workspaceStatus =
    capabilities.status === "loading" || capabilities.status === "idle"
      ? "Checking analysis access"
      : capabilities.status === "error"
        ? "Analysis access unavailable"
        : workspaceReady
          ? "Ready for evidence"
          : "Analysis unavailable";

  return (
    <div className="investigation-flow">
      <OverviewHero />

      <section className="workspace-state" aria-labelledby="workspace-state-title">
        <div className="workspace-state__heading">
          <p>Current workspace</p>
          <span className={workspaceReady ? "workspace-state__ready" : ""}>
            <i />{workspaceStatus}
          </span>
        </div>
        <div className="workspace-state__body">
          <span className="workspace-state__icon"><Icon name="shield" /></span>
          <div>
            <h2 id="workspace-state-title">No investigations yet</h2>
            <p>
              Analyze CloudTrail evidence to begin. A quiet workspace means no
              supported incident has been created here; it is not a statement
              about the safety of an AWS account.
            </p>
          </div>
        </div>
      </section>

      <GetStartedPanels
        capabilities={capabilities}
        queueCount={0}
        latestAnalysis={latestAnalysis}
        scannerResetToken={scannerResetToken}
        onAnalysisComplete={onAnalysisComplete}
        onClearAnalysis={onClearAnalysis}
        onDemoReset={onDemoReset}
        onOpenInvestigation={onOpenInvestigation}
      />

      <section className="zero-workflow" aria-labelledby="zero-evidence-title">
        <h2 id="zero-evidence-title">What TrailWeaver accepts</h2>
        <ul className="evidence-inputs">
          <li>
            <strong>CloudTrail file.</strong> A JSON export with a top-level{" "}
            <code>{"{\"Records\": [...]}"}</code> envelope. Gzipped JSON is accepted
            and uploads are limited to 10 MiB.
          </li>
          <li>
            <strong>AWS S3 object.</strong> An explicit bucket and object key,
            read with the backend&apos;s AWS identity — an instance profile,
            environment credentials, or container role. TrailWeaver never asks
            for access keys.
          </li>
          <li>
            <strong>Deterministic demo.</strong> A fictional
            account-compromise scenario served with{" "}
            <code>uvicorn trailweaver.api.demo:app --reload</code>. It is
            clearly labelled demo data and never real AWS evidence.
          </li>
        </ul>
        <p className="zero-cli">
          Prefer the terminal? The same pipeline runs through{" "}
          <code>trailweaver analyze-file export.json</code> and{" "}
          <code>trailweaver serve --host 127.0.0.1 --port 8000</code>.
        </p>
      </section>

      <section className="zero-workflow" aria-labelledby="zero-workflow-title">
        <h2 id="zero-workflow-title">How an investigation is produced</h2>
        <WorkflowStrip />
      </section>
    </div>
  );
}

function OverviewView({
  incidentCount,
  detail,
  risk,
  mitre,
  sortedTimeline,
  selectedSummary,
  capabilities,
  latestAnalysis,
  scannerResetToken,
  onOpenInvestigation,
  onAnalysisComplete,
  onClearAnalysis,
  onDemoReset,
  onOpenIncident,
}: {
  incidentCount: number;
  detail: Loadable<IncidentDetail>;
  risk: Loadable<RiskResponse>;
  mitre: Loadable<MitreResponse>;
  sortedTimeline: IncidentDetail["timeline"];
  selectedSummary: IncidentSummary | undefined;
  capabilities: Loadable<CapabilitiesResponse>;
  latestAnalysis: LatestAnalysis | null;
  scannerResetToken: number;
  onOpenInvestigation: () => void;
  onAnalysisComplete: (result: AnalysisResponse, source: "file" | "s3") => void;
  onClearAnalysis: () => void;
  onDemoReset: () => void;
  onOpenIncident: (incidentId: string) => void;
}) {
  const featuredTitle =
    detail.status === "success"
      ? detail.data.title
      : (selectedSummary?.title ?? "Incident details");
  const techniques = mitre.status === "success" ? mitre.data.techniques : [];
  const tactics = mitre.status === "success" ? mitre.data.tactics : [];

  return (
    <div className="investigation-flow">
      <OverviewHero
        populated={selectedSummary != null}
        onOpenInvestigation={onOpenInvestigation}
      />

      <div className="metrics" aria-label="Investigation summary">
        <MetricCard
          icon="incident"
          label="Incidents"
          value={String(incidentCount)}
          detail={incidentCount === 1 ? "Correlated case" : "Correlated cases"}
        />
        <MetricCard
          icon="shield"
          label="Featured risk"
          value={risk.status === "success" ? `${risk.data.score} / 100` : "Unavailable"}
          detail={risk.status === "success" ? titleCase(risk.data.level) : undefined}
          tone={risk.status === "success" && risk.data.level === "critical" ? "critical" : "neutral"}
          loading={risk.status === "loading"}
        />
        <MetricCard
          icon="signal"
          label="Correlated signals"
          value={detail.status === "success" ? String(detail.data.timeline.length) : "Unavailable"}
          detail="Observed sequence"
          loading={detail.status === "loading"}
        />
        <MetricCard
          icon="attack"
          label="ATT&CK techniques"
          value={mitre.status === "success" ? String(techniques.length) : "Unavailable"}
          detail={mitre.status === "success" ? `${tactics.length} ${tactics.length === 1 ? "tactic" : "tactics"}` : undefined}
          loading={mitre.status === "loading"}
        />
      </div>

      {selectedSummary ? (
      <section
        id="featured-investigation"
        className="featured-panel"
        aria-labelledby="featured-title"
      >
        <p className="featured-panel__kicker">Featured investigation</p>
        <div className="featured-panel__top">
          <h2 id="featured-title">{featuredTitle}</h2>
          {selectedSummary ? <SeverityBadge value={selectedSummary.severity} /> : null}
        </div>
        <div className="incident-metadata">
          <span>
            <Icon name="identity" />
            {detail.status === "success"
              ? actorLabel(detail.data)
              : detail.status === "loading"
                ? "Actor loading"
                : "Actor unavailable"}
          </span>
          <span>
            <Icon name="signal" />
            {detail.status === "success"
              ? `${formatDateTime(detail.data.started_at)} – ${formatDateTime(detail.data.ended_at)}`
              : detail.status === "loading"
                ? "Time range loading"
                : "Time range unavailable"}
          </span>
        </div>

        {detail.status === "loading" ? <PanelSkeleton rows={3} /> : null}
        {detail.status === "error" ? (
          <PanelError
            title="Featured investigation unavailable"
            message={detail.message}
          />
        ) : null}
        {detail.status === "success" && sortedTimeline.length > 0 ? (
          <ol className="evidence-steps" aria-label="Observed evidence sequence">
            {sortedTimeline.map((entry, index) => (
              <li key={entry.signal_id}>
                <span className="evidence-steps__number" aria-hidden="true">{index + 1}</span>
                <span className="evidence-steps__body">
                  <strong>{entry.title}</strong>
                  <time dateTime={entry.timestamp}>{formatTime(entry.timestamp)}</time>
                </span>
              </li>
            ))}
          </ol>
        ) : null}
        {mitre.status === "success" && techniques.length > 0 ? (
          <ul className="tag-chips" aria-label="Observed MITRE ATT&CK techniques">
            {techniques.map((technique) => (
              <li key={technique.technique_id}>
                <strong>{technique.technique_id}</strong> {technique.name}
              </li>
            ))}
          </ul>
        ) : null}

        <div className="featured-panel__actions">
          <button className="retry-button" type="button" onClick={onOpenInvestigation}>
            Open investigation
          </button>
        </div>
      </section>
      ) : null}

      <WelcomeCard />

      <GetStartedPanels
        capabilities={capabilities}
        queueCount={incidentCount}
        latestAnalysis={latestAnalysis}
        scannerResetToken={scannerResetToken}
        onAnalysisComplete={onAnalysisComplete}
        onClearAnalysis={onClearAnalysis}
        onDemoReset={onDemoReset}
        onOpenInvestigation={onOpenIncident}
      />

      <section className="zero-workflow" aria-labelledby="overview-workflow-title">
        <h2 id="overview-workflow-title">How an investigation is produced</h2>
        <WorkflowStrip />
      </section>
    </div>
  );
}

function IncidentsView({
  incidents,
  selectedIncidentId,
  onOpenInvestigation,
  onGoOverview,
}: {
  incidents: IncidentSummary[];
  selectedIncidentId: string | null;
  onOpenInvestigation: (incidentId: string) => void;
  onGoOverview: () => void;
}) {
  return (
    <div className="investigation-flow">
      <section className="overview-hero" aria-labelledby="incidents-title">
        <p className="overview-hero__kicker">TrailWeaver · Incidents</p>
        <h1 id="incidents-title">Incidents</h1>
        <p>
          Correlated cases from CloudTrail evidence. Opening a case selects
          it and enters its investigation.
        </p>
      </section>

      {incidents.length === 0 ? (
        <section className="empty-workspace" aria-labelledby="incidents-empty-title">
          <span className="empty-workspace__icon"><Icon name="incident" /></span>
          <p className="empty-workspace__kicker">Incident queue</p>
          <h1 id="incidents-empty-title">No incidents yet</h1>
          <p>
            Analyze CloudTrail evidence on the Overview to produce the first
            correlated case. A quiet queue means no supported incident has
            been created here; it is not a statement about the safety of an
            AWS account.
          </p>
          <button
            className="retry-button"
            type="button"
            onClick={onGoOverview}
          >
            Go to analysis
          </button>
        </section>
      ) : (
      <ul className="incident-cards">
        {incidents.map((incident) => {
          const selected = incident.incident_id === selectedIncidentId;
          return (
            <li
              key={incident.incident_id}
              className={selected ? "incident-card incident-card--selected" : "incident-card"}
            >
              <div className="incident-card__top">
                <SeverityBadge value={incident.severity} />
                {selected ? <span className="incident-card__selected">Selected</span> : null}
              </div>
              <h2>{incident.title}</h2>
              <p className="incident-card__id">{incident.incident_id}</p>
              <p className="incident-card__time">
                <time dateTime={incident.started_at}>{formatDateTime(incident.started_at)}</time>
                {" – "}
                <time dateTime={incident.ended_at}>{formatDateTime(incident.ended_at)}</time>
              </p>
              <div className="incident-card__actions">
                <button
                  type="button"
                  onClick={() => onOpenInvestigation(incident.incident_id)}
                >
                  Open investigation
                </button>
              </div>
            </li>
          );
        })}
      </ul>
      )}
    </div>
  );
}

function HistoryView({
  incidents,
  clearedAt,
  onClearHistory,
  onOpenInvestigation,
  onGoOverview,
}: {
  incidents: IncidentSummary[];
  clearedAt: string | null;
  onClearHistory: () => void;
  onOpenInvestigation: (incidentId: string) => void;
  onGoOverview: () => void;
}) {
  const recent = incidents.filter((incident) =>
    isRecentInvestigation(incident.created_at, clearedAt),
  );
  const [confirming, setConfirming] = useState(false);

  const confirmClear = () => {
    setConfirming(false);
    onClearHistory();
  };

  return (
    <div className="investigation-flow">
      <section className="overview-hero" aria-labelledby="history-title">
        <p className="overview-hero__kicker">TrailWeaver · History</p>
        <div className="history-head">
          <div>
            <h1 id="history-title">Recent Investigations</h1>
            <p>Investigations created in the past 24 hours.</p>
          </div>
          {recent.length > 0 && !confirming ? (
            <button
              type="button"
              className="analysis-complete__secondary"
              onClick={() => setConfirming(true)}
            >
              Clear history
            </button>
          ) : null}
        </div>
        {confirming ? (
          <div
            className="history-confirm"
            role="group"
            aria-label="Confirm clearing recent history"
          >
            <p><strong>Clear recent history?</strong></p>
            <p>
              This only clears the recent History view. Your saved
              investigations are not deleted.
            </p>
            <div className="history-confirm__actions">
              <button type="button" onClick={() => setConfirming(false)}>
                Cancel
              </button>
              <button type="button" onClick={confirmClear}>
                Clear history
              </button>
            </div>
          </div>
        ) : null}
      </section>

      {recent.length === 0 ? (
        <section className="empty-workspace" aria-labelledby="history-empty-title">
          <span className="empty-workspace__icon"><Icon name="history" /></span>
          <p className="empty-workspace__kicker">Recent history</p>
          <h1 id="history-empty-title">No investigations in your recent history.</h1>
          <p>
            History shows persisted investigations created in the past 24
            hours. Older investigations stay saved and remain available from
            the incident queue.
          </p>
          <button
            className="retry-button"
            type="button"
            onClick={onGoOverview}
          >
            Analyze CloudTrail
          </button>
        </section>
      ) : (
      <ul className="incident-cards">
        {recent.map((incident) => (
          <li key={incident.incident_id} className="incident-card">
            <div className="incident-card__top">
              <SeverityBadge value={incident.severity} />
            </div>
            <h2>{incident.title}</h2>
            <p className="incident-card__id">{incident.incident_id}</p>
            <p className="incident-card__time">
              Created <time dateTime={incident.created_at}>{formatDateTime(incident.created_at)}</time>
            </p>
            <div className="incident-card__actions">
              <button
                type="button"
                onClick={() => onOpenInvestigation(incident.incident_id)}
              >
                Open investigation
              </button>
            </div>
          </li>
        ))}
      </ul>
      )}
    </div>
  );
}

export function InvestigationDashboard() {
  const [incidents, setIncidents] = useState<Loadable<IncidentSummary[]>>(loading());
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Loadable<IncidentDetail>>(idle());
  const [risk, setRisk] = useState<Loadable<RiskResponse>>(idle());
  const [mitre, setMitre] = useState<Loadable<MitreResponse>>(idle());
  const [blastRadius, setBlastRadius] = useState<Loadable<BlastRadiusResponse>>(idle());
  const [guidance, setGuidance] = useState<Loadable<GuidanceResponse>>(idle());
  const [graph, setGraph] = useState<Loadable<GraphResponse>>(idle());
  const [provenance, setProvenance] = useState<Loadable<IncidentProvenance>>(idle());
  const [route, setRoute] = useState<Route>(
    () => parseRouteHash(window.location.hash) ?? readStoredRoute() ?? "overview",
  );
  const [capabilities, setCapabilities] =
    useState<Loadable<CapabilitiesResponse>>(loading());
  const [backendStatus, setBackendStatus] = useState<BackendStatus>("checking");
  const [latestAnalysis, setLatestAnalysis] = useState<LatestAnalysis | null>(null);
  const [scannerEpoch, setScannerEpoch] = useState(0);
  const [historyClearedAt, setHistoryClearedAt] = useState<string | null>(
    () => readHistoryClearedAt(),
  );
  const incidentsLoadedRef = useRef(false);
  const capabilitiesLoadedRef = useRef(false);
  const [listReload, setListReload] = useState(0);
  const [detailReload, setDetailReload] = useState(0);
  const [riskReload, setRiskReload] = useState(0);
  const [mitreReload, setMitreReload] = useState(0);
  const [blastReload, setBlastReload] = useState(0);
  const [guidanceReload, setGuidanceReload] = useState(0);
  const [graphReload, setGraphReload] = useState(0);
  const [provenanceReload, setProvenanceReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    // Background queue reloads must never unmount the workspace: the
    // latest analysis result lives above this fetch, and the loading splash
    // replaces the whole app. Only the initial mount uses the splash.
    if (!incidentsLoadedRef.current) {
      setIncidents(loading());
      setBackendStatus("checking");
    }

    trailWeaverApi
      .health(controller.signal)
      .then(() => setBackendStatus("online"))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setBackendStatus("offline");
        }
      });

    trailWeaverApi
      .listIncidents(controller.signal)
      .then((items) => {
        incidentsLoadedRef.current = true;
        setIncidents({ status: "success", data: items });
        setSelectedIncidentId((current) => {
          if (current && items.some((item) => item.incident_id === current)) {
            return current;
          }
          return items[items.length - 1]?.incident_id ?? null;
        });
      })
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          incidentsLoadedRef.current = true;
          setBackendStatus("offline");
          // A background refresh failure keeps previously loaded data on
          // screen instead of tearing down the workspace (and any visible
          // analysis result) with the full error state.
          setIncidents((previous) =>
            previous.status === "success"
              ? previous
              : { status: "error", message: errorMessage(error) },
          );
        }
      });

    return () => controller.abort();
  }, [listReload]);

  useEffect(() => {
    const controller = new AbortController();
    // Same stale-while-revalidate treatment as the queue: a capabilities
    // refresh must not flip the analysis cards to "Checking availability…"
    // while a result is on screen.
    if (!capabilitiesLoadedRef.current) {
      setCapabilities(loading());
    }

    trailWeaverApi
      .capabilities(controller.signal)
      .then((data) => {
        capabilitiesLoadedRef.current = true;
        setCapabilities({ status: "success", data });
      })
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          capabilitiesLoadedRef.current = true;
          setCapabilities((previous) =>
            previous.status === "success"
              ? previous
              : { status: "error", message: errorMessage(error) },
          );
        }
      });

    return () => controller.abort();
  }, [listReload]);

  useEffect(() => {
    // Canonicalize the URL on load so refresh never leaves URL and UI disagreeing.
    if (parseRouteHash(window.location.hash) === null) {
      const fallback = readStoredRoute() ?? "overview";
      window.location.replace(ROUTE_HASHES[fallback]);
      setRoute(fallback);
      return;
    }

    const onHashChange = () => {
      const parsed = parseRouteHash(window.location.hash);
      if (parsed === null) return;
      setRoute(parsed);
      try {
        window.sessionStorage.setItem(ROUTE_STORAGE_KEY, parsed);
      } catch {
        // Route persistence is best-effort when storage is unavailable.
      }
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (!selectedIncidentId) {
      setDetail(idle());
      return;
    }

    const controller = new AbortController();
    setDetail(loading());

    trailWeaverApi
      .getIncident(selectedIncidentId, controller.signal)
      .then((data) => setDetail({ status: "success", data }))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setDetail({ status: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [detailReload, selectedIncidentId]);

  useEffect(() => {
    if (!selectedIncidentId) {
      setRisk(idle());
      return;
    }

    const controller = new AbortController();
    setRisk(loading());

    trailWeaverApi
      .getRisk(selectedIncidentId, controller.signal)
      .then((data) => setRisk({ status: "success", data }))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setRisk({ status: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [riskReload, selectedIncidentId]);

  useEffect(() => {
    if (!selectedIncidentId) {
      setMitre(idle());
      return;
    }

    const controller = new AbortController();
    setMitre(loading());

    trailWeaverApi
      .getMitre(selectedIncidentId, controller.signal)
      .then((data) => setMitre({ status: "success", data }))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setMitre({ status: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [mitreReload, selectedIncidentId]);

  useEffect(() => {
    if (!selectedIncidentId) {
      setBlastRadius(idle());
      return;
    }

    const controller = new AbortController();
    setBlastRadius(loading());

    trailWeaverApi
      .getBlastRadius(selectedIncidentId, controller.signal)
      .then((data) => setBlastRadius({ status: "success", data }))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setBlastRadius({ status: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [blastReload, selectedIncidentId]);

  useEffect(() => {
    if (!selectedIncidentId) {
      setGuidance(idle());
      return;
    }

    const controller = new AbortController();
    setGuidance(loading());

    trailWeaverApi
      .getGuidance(selectedIncidentId, controller.signal)
      .then((data) => setGuidance({ status: "success", data }))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setGuidance({ status: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [guidanceReload, selectedIncidentId]);

  useEffect(() => {
    if (!selectedIncidentId) {
      setGraph(idle());
      return;
    }

    const controller = new AbortController();
    setGraph(loading());

    trailWeaverApi
      .getGraph(selectedIncidentId, controller.signal)
      .then((data) => setGraph({ status: "success", data }))
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setGraph({ status: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [graphReload, selectedIncidentId]);

  useEffect(() => {
    // Provenance stays local to its panel: it never blocks the timeline
    // or any other investigation section. The cancellation flag covers the
    // resolved-before-abort race so a stale selection cannot overwrite the
    // newly selected incident's provenance.
    if (!selectedIncidentId) {
      setProvenance(idle());
      return;
    }

    const controller = new AbortController();
    let cancelled = false;
    setProvenance(loading());

    trailWeaverApi
      .getProvenance(selectedIncidentId, controller.signal)
      .then((data) => {
        if (!cancelled) setProvenance({ status: "success", data });
      })
      .catch((error: unknown) => {
        if (!cancelled && !(error instanceof Error && error.name === "AbortError")) {
          setProvenance({ status: "error", message: errorMessage(error) });
        }
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [provenanceReload, selectedIncidentId]);

  const selectedSummary = useMemo(() => {
    if (incidents.status !== "success") return undefined;
    return incidents.data.find((item) => item.incident_id === selectedIncidentId);
  }, [incidents, selectedIncidentId]);

  const sortedTimeline = useMemo(() => {
    if (detail.status !== "success") return [];
    return orderTimelineEntries(detail.data.timeline);
  }, [detail]);

  const demoMode =
    capabilities.status === "success" && capabilities.data.demo_mode;

  const assetCounts = useMemo(() => {
    if (
      blastRadius.status !== "success" ||
      !blastRadius.data.available
    ) {
      return [];
    }
    const counts = new Map<string, number>();
    for (const asset of blastRadius.data.reachable_assets) {
      counts.set(asset.asset_type, (counts.get(asset.asset_type) ?? 0) + 1);
    }
    return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [blastRadius]);

  const scrollWorkspaceTop = () => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top: 0, behavior: reduced ? "auto" : "smooth" });
  };

  const applyRoute = (next: Route) => {
    setRoute(next);
    try {
      window.sessionStorage.setItem(ROUTE_STORAGE_KEY, next);
    } catch {
      // Route persistence is best-effort when storage is unavailable.
    }
  };

  const navigate = (hash: string) => {
    const parsed = parseRouteHash(hash);
    if (window.location.hash === hash) {
      if (parsed !== null) applyRoute(parsed);
    } else {
      // The hashchange listener applies the route; in-page anchors are ignored.
      window.location.hash = hash;
    }
    scrollWorkspaceTop();
  };

  const openInvestigation = (incidentId: string) => {
    // Opening an investigation ends the latest-result lifecycle: the analyst
    // has moved from the analysis outcome to the investigation itself.
    setLatestAnalysis(null);
    setSelectedIncidentId(incidentId);
    navigate(ROUTE_HASHES.investigation);
  };

  const closeInvestigation = () => {
    // Navigation and transient UI state only: the selection is dropped, any
    // lingering analysis result is cleared, and the file scanner is asked
    // back to its initial state. Persisted incidents, the queue, SQLite,
    // backend state, and AWS are all untouched — the incident stays
    // reopenable from the queue.
    setSelectedIncidentId(null);
    setLatestAnalysis(null);
    setScannerEpoch((value) => value + 1);
    navigate(ROUTE_HASHES.overview);
  };

  const handleAnalysisComplete = (result: AnalysisResponse, source: "file" | "s3") => {
    // The completed analysis result is lifted above the queue reload, so the
    // background refresh below can never unmount or hide it. The result stays
    // on screen until another analysis replaces it, the analyst clears it, or
    // an investigation is opened.
    setLatestAnalysis({ source, result });
    setListReload((value) => value + 1);
  };

  const handleClearAnalysis = () => {
    setLatestAnalysis(null);
  };

  const handleClearHistory = () => {
    // UI dismissal only: currently visible History entries are hidden behind
    // a session-level watermark. Persisted incidents, the queue, SQLite, and
    // backend state are untouched, and later investigations still appear.
    // A queue refresh cannot restore dismissed entries because the filter
    // applies at render time.
    const now = new Date().toISOString();
    try {
      window.sessionStorage.setItem(HISTORY_CLEARED_STORAGE_KEY, now);
    } catch {
      // The watermark is best-effort when storage is unavailable.
    }
    setHistoryClearedAt(now);
  };

  const handleDemoReset = () => {
    // Resetting the demo workspace ends any latest-result lifecycle and
    // drops the incident selection so the workspace returns to its clean
    // initial state; the queue reload below repopulates the empty overview.
    setLatestAnalysis(null);
    setSelectedIncidentId(null);
    setListReload((value) => value + 1);
  };

  const [clearConfirming, setClearConfirming] = useState(false);
  const [clearState, setClearState] = useState<Loadable<never>>(idle());

  const cancelClearWorkspace = () => {
    setClearConfirming(false);
    setClearState(idle());
  };

  const confirmClearWorkspace = () => {
    setClearState(loading());
    trailWeaverApi
      .clearWorkspace()
      .then(() => {
        // Only erase UI state after the backend confirms: selection and the
        // latest result are dropped, the queue reloads, and an investigation
        // route steps back to the overview so no stale data stays on screen.
        setClearConfirming(false);
        setClearState(idle());
        setLatestAnalysis(null);
        setSelectedIncidentId(null);
        if (route === "investigation" || route === "graph") {
          navigate(ROUTE_HASHES.overview);
        }
        setListReload((value) => value + 1);
      })
      .catch((error: unknown) => {
        setClearState({ status: "error", message: errorMessage(error) });
      });
  };

  const returnToOverview = (sectionId: string) => {
    // Section navigation stays inside the current unified investigation.
    // It never writes location.hash, so the route, selection, and
    // graph/replay state remain coherent.
    scrollToInvestigationSection(sectionId);
  };

  const viewTimelineSignal = (signalId: string) => {
    // Signal-ID linkage: the exact observed evidence, not timestamp matching.
    // Stays on the unified investigation page; never navigates away.
    if (route !== "investigation" && route !== "graph") {
      navigate(ROUTE_HASHES.investigation);
    }
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const entry = document.getElementById(timelineAnchorId(signalId));
        entry?.scrollIntoView({
          behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
            ? "auto"
            : "smooth",
          block: "center",
        });
        entry?.focus({ preventScroll: true });
      });
    });
  };

  // Compatibility: the legacy #/investigation/graph route renders the same
  // unified page and focuses the reconstruction section once it exists.
  useEffect(() => {
    if (route !== "graph" || !selectedIncidentId) return;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        scrollToInvestigationSection(INVESTIGATION_SECTIONS.reconstruction);
      });
    });
  }, [route, selectedIncidentId]);

  if (incidents.status === "loading") {
    return (
      <div className="app-loading">
        <div className="app-loading__brand"><span>TW</span> TrailWeaver</div>
        <div
          className="app-loading__shell"
          role="status"
          aria-label="Loading incident workspace"
          aria-busy="true"
          aria-live="polite"
        >
          <span aria-hidden="true" /><span aria-hidden="true" />
          <span aria-hidden="true" /><span aria-hidden="true" />
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#workspace-content">Skip to content</a>
      <aside className="sidebar" aria-label="TrailWeaver navigation">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true"><i /><i /><i /></span>
          <span>TrailWeaver</span>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <button
            type="button"
            className={route === "overview" ? "primary-nav__item--active" : undefined}
            aria-current={route === "overview" ? "page" : undefined}
            onClick={() => navigate(ROUTE_HASHES.overview)}
          >
            <Icon name="overview" />Overview
          </button>
          <button
            type="button"
            className={route === "incidents" ? "primary-nav__item--active" : undefined}
            aria-current={route === "incidents" ? "page" : undefined}
            onClick={() => navigate(ROUTE_HASHES.incidents)}
          >
            <Icon name="incident" />Incidents
          </button>
          <button
            type="button"
            className={route === "history" ? "primary-nav__item--active" : undefined}
            aria-current={route === "history" ? "page" : undefined}
            onClick={() => navigate(ROUTE_HASHES.history)}
          >
            <Icon name="history" />History
          </button>
          <button
            type="button"
            className={
              route === "investigation" || route === "graph"
                ? "primary-nav__item--active"
                : undefined
            }
            aria-current={
              route === "investigation" || route === "graph" ? "page" : undefined
            }
            onClick={() => navigate(ROUTE_HASHES.investigation)}
          >
            <Icon name="search" />Investigation
          </button>
        </nav>

        <section className="incident-queue" aria-labelledby="incident-queue-title">
          <div className="incident-queue__header">
            <h2 id="incident-queue-title">Incidents</h2>
            <div className="incident-queue__actions">
              {incidents.status === "success" ? <span>{incidents.data.length}</span> : null}
              <button
                type="button"
                className="queue-reload"
                onClick={() => setListReload((value) => value + 1)}
                aria-label="Reload incident queue"
              >
                Reload
              </button>
            </div>
          </div>
          {incidents.status === "error" ? (
            <div className="sidebar-error">
              <p>Incidents could not be loaded.</p>
              <button type="button" onClick={() => setListReload((value) => value + 1)}>
                Retry connection
              </button>
            </div>
          ) : null}
          {incidents.status === "success" && incidents.data.length === 0 ? (
            <div className="sidebar-empty">
              <Icon name="shield" />
              <p>No incidents yet</p>
              <span>New correlated incidents will appear here.</span>
            </div>
          ) : null}
          {incidents.status === "success" ? (
            <div className="incident-list">
              {incidents.data.map((incident) => {
                const selected = incident.incident_id === selectedIncidentId;
                return (
                  <button
                    type="button"
                    key={incident.incident_id}
                    className={selected ? "incident-option incident-option--selected" : "incident-option"}
                    aria-current={selected || undefined}
                    aria-label={`${selected ? "Selected: " : "Open investigation: "}${incident.title}`}
                    onClick={() => openInvestigation(incident.incident_id)}
                  >
                    <span className="incident-option__topline">
                      <SeverityBadge value={incident.severity} />
                      <time dateTime={incident.started_at}>{formatDateTime(incident.started_at)}</time>
                    </span>
                    <strong>{incident.title}</strong>
                    <span className="incident-option__id">{incident.incident_id}</span>
                  </button>
                );
              })}
            </div>
          ) : null}
          {!demoMode && incidents.status !== "error" ? (
            <div className="queue-clear">
              {clearConfirming ? (
                <div
                  className="queue-clear__confirm"
                  role="group"
                  aria-label="Confirm clearing the investigation workspace"
                  tabIndex={-1}
                  ref={(node) => node?.focus()}
                  onKeyDown={(event) => {
                    if (event.key === "Escape") cancelClearWorkspace();
                  }}
                >
                  <p><strong>Clear investigation workspace?</strong></p>
                  <p>
                    This removes TrailWeaver&apos;s persisted incidents and
                    investigation state. It does not delete your original
                    CloudTrail files or anything from AWS.
                  </p>
                  {clearState.status === "error" ? (
                    <p className="queue-clear__error" role="alert">{clearState.message}</p>
                  ) : null}
                  <div className="queue-clear__actions">
                    <button type="button" onClick={cancelClearWorkspace}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="queue-clear__confirm-button"
                      disabled={clearState.status === "loading"}
                      onClick={confirmClearWorkspace}
                    >
                      {clearState.status === "loading"
                        ? "Clearing…"
                        : clearState.status === "error"
                          ? "Retry clearing"
                          : "Clear workspace"}
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  type="button"
                  className="queue-clear__trigger"
                  onClick={() => setClearConfirming(true)}
                >
                  Clear workspace
                </button>
              )}
            </div>
          ) : null}
        </section>

        <div className="sidebar-profile">
          <span aria-hidden="true">TW</span>
          <div><strong>Local analyst</strong><small>Investigation workspace</small></div>
        </div>
      </aside>

      <main className="workspace" id="workspace-content" tabIndex={-1}>
        <header className="workspace-toolbar">
          <nav className="breadcrumb" aria-label="Breadcrumb">
            {route === "overview" ? (
              <span>Overview</span>
            ) : route === "incidents" ? (
              <span>Incidents</span>
            ) : route === "history" ? (
              <span>History</span>
            ) : (
              <>
                <span>Investigation</span><b aria-hidden="true">/</b>{selectedIncidentId ?? "No selection"}
              </>
            )}
          </nav>
          <div
            className={`backend-status backend-status--${backendStatus}`}
            role="status"
            aria-live="polite"
          >
            <span aria-hidden="true" />
            {backendStatus === "checking" ? "Checking API" : backendStatus === "online" ? "API connected" : "API unavailable"}
          </div>
        </header>

        {incidents.status === "success" && incidents.data.length === 0 && route === "overview" ? (
          <ZeroIncidentPanel
            capabilities={capabilities}
            latestAnalysis={latestAnalysis}
            scannerResetToken={scannerEpoch}
            onAnalysisComplete={handleAnalysisComplete}
            onClearAnalysis={handleClearAnalysis}
            onDemoReset={handleDemoReset}
            onOpenInvestigation={openInvestigation}
          />
        ) : null}

        {incidents.status === "success" && incidents.data.length === 0 && route === "incidents" ? (
          <IncidentsView
            incidents={[]}
            selectedIncidentId={null}
            onOpenInvestigation={(incidentId) => openInvestigation(incidentId)}
            onGoOverview={() => navigate(ROUTE_HASHES.overview)}
          />
        ) : null}

        {incidents.status === "success" && incidents.data.length === 0 && (route === "investigation" || route === "graph") ? (
          <div className="investigation-flow">
            <section className="empty-workspace" aria-labelledby="no-analysis-title">
              <span className="empty-workspace__icon"><Icon name="incident" /></span>
              <p className="empty-workspace__kicker">Investigation</p>
              <h1 id="no-analysis-title">No investigations yet</h1>
              <p>
                Analyze CloudTrail evidence on the Overview first. Timeline,
                risk, MITRE ATT&amp;CK, attack graph, replay, blast radius,
                and guidance appear here once a correlated incident exists.
              </p>
              <button
                className="retry-button"
                type="button"
                onClick={() => navigate(ROUTE_HASHES.overview)}
              >
                Go to analysis
              </button>
            </section>
          </div>
        ) : null}

        {incidents.status === "error" ? (
          <section className="empty-workspace empty-workspace--error" role="alert">
            <span className="empty-workspace__icon"><Icon name="alert" /></span>
            <p className="empty-workspace__kicker">API unavailable</p>
            <h1>Incident queue could not be loaded</h1>
            <p>{incidents.message}</p>
            <button
              className="retry-button"
              type="button"
              onClick={() => setListReload((value) => value + 1)}
            >
              Retry connection
            </button>
          </section>
        ) : null}

        {incidents.status === "success" && incidents.data.length > 0 && route === "overview" ? (
          <OverviewView
            incidentCount={incidents.data.length}
            detail={detail}
            risk={risk}
            mitre={mitre}
            sortedTimeline={sortedTimeline}
            selectedSummary={selectedSummary}
            capabilities={capabilities}
            latestAnalysis={latestAnalysis}
            scannerResetToken={scannerEpoch}
            onOpenInvestigation={() => {
              if (selectedIncidentId) openInvestigation(selectedIncidentId);
            }}
            onAnalysisComplete={handleAnalysisComplete}
            onClearAnalysis={handleClearAnalysis}
            onDemoReset={handleDemoReset}
            onOpenIncident={(incidentId) => openInvestigation(incidentId)}
          />
        ) : null}

        {incidents.status === "success" && route === "history" ? (
          <HistoryView
            incidents={incidents.data}
            clearedAt={historyClearedAt}
            onClearHistory={handleClearHistory}
            onOpenInvestigation={(incidentId) => openInvestigation(incidentId)}
            onGoOverview={() => navigate(ROUTE_HASHES.overview)}
          />
        ) : null}

        {incidents.status === "success" && incidents.data.length > 0 && route === "incidents" ? (
          <IncidentsView
            incidents={incidents.data}
            selectedIncidentId={selectedIncidentId}
            onOpenInvestigation={(incidentId) => openInvestigation(incidentId)}
            onGoOverview={() => navigate(ROUTE_HASHES.overview)}
          />
        ) : null}

        {incidents.status === "success" && incidents.data.length > 0 && (route === "investigation" || route === "graph") && !selectedIncidentId ? (
          <div className="investigation-flow">
            <section className="empty-workspace" aria-labelledby="select-incident-title">
              <span className="empty-workspace__icon"><Icon name="incident" /></span>
              <p className="empty-workspace__kicker">Investigation</p>
              <h1 id="select-incident-title">Select an incident to investigate</h1>
              <p>
                Timeline, risk, MITRE ATT&amp;CK, attack graph, replay, blast
                radius, and guidance are available once an incident is selected.
              </p>
              <button
                className="retry-button"
                type="button"
                onClick={() => navigate(ROUTE_HASHES.incidents)}
              >
                Go to incidents
              </button>
            </section>
          </div>
        ) : null}

        {incidents.status === "success" && incidents.data.length > 0 && (route === "investigation" || route === "graph") && selectedIncidentId ? (
          <>
            <div className="investigation-flow">
              <section
                className="investigation-section incident-section"
                id={INVESTIGATION_SECTIONS.overview}
                aria-labelledby="incident-title"
                tabIndex={-1}
              >
                <header className="incident-header">
                  <div className="incident-header__top">
                    <p className="incident-header__lead">Investigating</p>
                    <button
                      type="button"
                      className="analysis-complete__secondary"
                      onClick={closeInvestigation}
                    >
                      Close investigation
                    </button>
                  </div>
                  <h1 id="incident-title">
                    {detail.status === "success" ? detail.data.title : selectedSummary?.title ?? "Incident details"}
                  </h1>
                  <div className="incident-metadata">
                    <span><Icon name="incident" />{selectedIncidentId}</span>
                    <span>
                      <Icon name="identity" />
                      {detail.status === "success"
                        ? actorLabel(detail.data)
                        : detail.status === "loading"
                          ? "Actor loading"
                          : "Actor unavailable"}
                    </span>
                    <span>
                      <Icon name="signal" />
                      {detail.status === "success"
                        ? `${formatDateTime(detail.data.started_at)} – ${formatDateTime(detail.data.ended_at)}`
                        : detail.status === "loading"
                          ? "Time range loading"
                          : "Time range unavailable"}
                    </span>
                  </div>
                </header>

                <div className="metrics" aria-label="Incident summary">
                  <MetricCard
                    icon="shield"
                    label="Risk score"
                    value={risk.status === "success" ? `${risk.data.score} / 100` : "Unavailable"}
                    detail={risk.status === "success" ? titleCase(risk.data.level) : undefined}
                    tone={risk.status === "success" && risk.data.level === "critical" ? "critical" : "neutral"}
                    loading={risk.status === "loading"}
                  />
                  <MetricCard
                    icon="alert"
                    label="Incident severity"
                    value={detail.status === "success" ? titleCase(detail.data.severity) : selectedSummary ? titleCase(selectedSummary.severity) : "Unavailable"}
                    tone={selectedSummary?.severity.toLowerCase() === "high" ? "high" : "neutral"}
                    loading={detail.status === "loading" && !selectedSummary}
                  />
                  <MetricCard
                    icon="signal"
                    label="Correlated signals"
                    value={detail.status === "success" ? String(detail.data.timeline.length) : "Unavailable"}
                    detail="Observed sequence"
                    loading={detail.status === "loading"}
                  />
                  <MetricCard
                    icon="cloud"
                    label="Potentially reachable assets"
                    value={
                      blastRadius.status === "success" && blastRadius.data.available
                        ? String(blastRadius.data.total_reachable_assets)
                        : "Unavailable"
                    }
                    detail={
                      blastRadius.status === "success"
                        ? blastRadius.data.available
                          ? blastRadius.data.total_reachable_assets === 0
                            ? "No known reachability"
                            : "Known context only"
                          : "Cloud context missing"
                        : blastRadius.status === "error"
                          ? "Request failed"
                          : undefined
                    }
                    loading={blastRadius.status === "loading"}
                  />
                </div>

                <nav className="section-nav" aria-label="Investigation sections">
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.overview)}>Overview</button>
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.timeline)}>Timeline</button>
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.provenance)}>Provenance</button>
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.analysis)}>Risk + ATT&amp;CK</button>
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.reconstruction)}>Graph + Replay</button>
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.blast)}>Potential impact</button>
                  <button type="button" onClick={() => returnToOverview(INVESTIGATION_SECTIONS.guidance)}>Guidance</button>
                </nav>
              </section>

              <section
                className="investigation-section timeline-panel"
                id={INVESTIGATION_SECTIONS.timeline}
                aria-labelledby="timeline-title"
                tabIndex={-1}
              >
                <div className="timeline-panel__top">
                  <PanelHeading
                    id="timeline-title"
                    title="Incident Timeline"
                    description="Key observed signals in this investigation, in chronological order."
                  />
                  <span className="timeline-panel__filter">Observed signals <b>{sortedTimeline.length || "—"}</b></span>
                </div>
                <div className="timeline-panel__body">
                  {detail.status === "loading" ? <PanelSkeleton rows={4} /> : null}
                  {detail.status === "error" ? (
                    <PanelError
                      title="Timeline unavailable"
                      message={detail.message}
                      onRetry={() => setDetailReload((value) => value + 1)}
                    />
                  ) : null}
                  {detail.status === "success" && sortedTimeline.length === 0 ? (
                    <div className="dark-empty"><Icon name="signal" /><p>No timeline entries are available for this incident.</p></div>
                  ) : null}
                  {detail.status === "success" && sortedTimeline.length > 0 ? (
                    <ol className="timeline-list">
                      {sortedTimeline.map((entry, index) => (
                        <li
                          key={entry.signal_id}
                          id={timelineAnchorId(entry.signal_id)}
                          tabIndex={-1}
                        >
                          <div className="timeline-node" aria-hidden="true">{index + 1}</div>
                          <time dateTime={entry.timestamp}>{formatTime(entry.timestamp)}</time>
                          <div className="timeline-event">
                            <h3>{entry.title}</h3>
                            <p>{entry.reason}</p>
                            <span className="rule-chip">{entry.rule_id}</span>
                          </div>
                        </li>
                      ))}
                    </ol>
                  ) : null}
                  {detail.status === "success" && sortedTimeline.length > 0 ? (
                    <div className="timeline-complete">
                      <span aria-hidden="true">✓</span>
                      <div>
                        <strong>End of observed sequence</strong>
                        <p>{sortedTimeline.length} observed signals over {incidentDuration(detail.data)}</p>
                      </div>
                    </div>
                  ) : null}
                </div>
              </section>

              <section
                className="investigation-section provenance-section"
                id={INVESTIGATION_SECTIONS.provenance}
                aria-labelledby="provenance-title"
                tabIndex={-1}
              >
                <EvidenceProvenancePanel
                  provenance={provenance}
                  onRetry={() => setProvenanceReload((value) => value + 1)}
                />
              </section>

              <section
                className="investigation-section meaning-section"
                id={INVESTIGATION_SECTIONS.analysis}
                aria-labelledby="meaning-title"
                tabIndex={-1}
              >
                <SectionHeading
                  id="meaning-title"
                  title="Why this matters"
                  description="Deterministic risk and ATT&CK context derived from the observed sequence."
                />
                <div className="meaning-grid">
                  <section className="analysis-panel risk-panel" aria-labelledby="risk-title">
                    <PanelHeading
                      id="risk-title"
                      title="Risk explanation"
                      description="Deterministic total from observed signals."
                      level="h3"
                    />
                    {risk.status === "loading" ? <PanelSkeleton /> : null}
                    {risk.status === "error" ? (
                      <PanelError
                        title="Risk explanation unavailable"
                        message={risk.message}
                        onRetry={() => setRiskReload((value) => value + 1)}
                      />
                    ) : null}
                    {risk.status === "success" ? (
                      <div className="risk-layout">
                        <div className="risk-total">
                          <p>Risk</p>
                          <strong>{risk.data.score}<span>/100</span></strong>
                          <SeverityBadge value={risk.data.level} />
                        </div>
                        <div className="risk-factor-list">
                          {risk.data.factors.length === 0 ? <p>No contributing factors were returned.</p> : null}
                          {risk.data.factors.map((factor) => (
                            <div key={factor.identifier}>
                              <strong>{factor.points >= 0 ? "+" : ""}{factor.points}</strong>
                              <span>{factor.description}</span>
                            </div>
                          ))}
                        </div>
                        <p className="risk-explanation">{risk.data.explanation}</p>
                      </div>
                    ) : null}
                  </section>

                  <section className="analysis-panel mitre-panel" aria-labelledby="mitre-title">
                    <PanelHeading
                      id="mitre-title"
                      title="Observed ATT&CK mappings"
                      description="Techniques mapped from observed behavior; not proof of intent."
                      level="h3"
                    />
                    {mitre.status === "loading" ? <PanelSkeleton /> : null}
                    {mitre.status === "error" ? (
                      <PanelError
                        title="ATT&CK mappings unavailable"
                        message={mitre.message}
                        onRetry={() => setMitreReload((value) => value + 1)}
                      />
                    ) : null}
                    {mitre.status === "success" && mitre.data.techniques.length === 0 ? (
                      <div className="light-empty"><p>No ATT&CK techniques were mapped from the observed signals.</p></div>
                    ) : null}
                    {mitre.status === "success" ? (
                      <div className="mitre-list">
                        {mitre.data.techniques.map((technique) => (
                          <article key={technique.technique_id}>
                            <div><strong>{technique.technique_id}</strong><h4>{technique.name}</h4></div>
                            <p>{technique.description}</p>
                            <div className="tactic-list">
                              {technique.tactics.map((tactic) => <span key={tactic}>{tactic}</span>)}
                            </div>
                          </article>
                        ))}
                      </div>
                    ) : null}
                  </section>
                </div>
              </section>

              <section
                className="investigation-section reconstruction-section"
                id={INVESTIGATION_SECTIONS.reconstruction}
                aria-labelledby="reconstruction-title"
                tabIndex={-1}
              >
                <SectionHeading
                  id="reconstruction-title"
                  title="Attack reconstruction"
                  description="Observed relationships reconstructed from this incident's evidence. The full graph shows everything observed; replay reveals the same observed evidence chronologically. Potential reachability lives under Potential impact — never in this graph or replay."
                />
                {graph.status === "loading" ? (
                  <div className="graph-workspace graph-workspace--state" role="status" aria-label="Loading attack graph" aria-busy="true" aria-live="polite">
                    <PanelSkeleton rows={5} />
                  </div>
                ) : null}
                {graph.status === "error" ? (
                  <div className="graph-workspace graph-workspace--state">
                    <PanelError
                      title="Attack graph unavailable"
                      message={graph.message}
                      onRetry={() => setGraphReload((value) => value + 1)}
                    />
                  </div>
                ) : null}
                {graph.status === "success" && graph.data.nodes.length === 0 ? (
                  <div className="graph-workspace graph-workspace--state">
                    <div className="dark-empty">
                      <Icon name="attack" />
                      <p>No observed relationships were reconstructed for this incident. Nothing was invented to fill the gap.</p>
                    </div>
                  </div>
                ) : null}
                {graph.status === "success" && graph.data.nodes.length > 0 ? (
                  <AttackGraphView
                    key={selectedIncidentId}
                    graph={graph.data}
                    timeline={sortedTimeline}
                    onViewTimeline={viewTimelineSignal}
                  />
                ) : null}
              </section>

              <section
                className="investigation-section impact-section"
                id={INVESTIGATION_SECTIONS.blast}
                aria-labelledby="impact-title"
                tabIndex={-1}
              >
                <SectionHeading
                  id="impact-title"
                  title="Potential impact"
                  description="Known assets this identity may be able to reach. This is context, not evidence of access."
                />
                <div className="analysis-panel blast-panel" aria-labelledby="blast-title">
                  <PanelHeading
                    id="blast-title"
                    title="Potentially reachable known assets"
                    description="Reachability over loaded cloud context; not observed access."
                    level="h3"
                  />
                  {blastRadius.status === "loading" ? <PanelSkeleton /> : null}
                  {blastRadius.status === "error" ? (
                    <PanelError
                      title="Reachability unavailable"
                      message={blastRadius.message}
                      onRetry={() => setBlastReload((value) => value + 1)}
                    />
                  ) : null}
                  {blastRadius.status === "success" && !blastRadius.data.available ? (
                    <div className="blast-state blast-state--unavailable">
                      <Icon name="cloud" />
                      <h4>Cloud context unavailable</h4>
                      <p>{blastRadius.data.reason} Potential reachability cannot be calculated.</p>
                    </div>
                  ) : null}
                  {blastRadius.status === "success" && blastRadius.data.available && blastRadius.data.total_reachable_assets === 0 ? (
                    <div className="blast-state blast-state--empty">
                      <Icon name="shield" />
                      <h4>No known reachable assets identified</h4>
                      <p>Context is available, but no loaded assets matched the incident identity’s explicit grants.</p>
                    </div>
                  ) : null}
                  {blastRadius.status === "success" && blastRadius.data.available && blastRadius.data.total_reachable_assets > 0 ? (
                    <div className="blast-results">
                      <div className="blast-total"><strong>{blastRadius.data.total_reachable_assets}</strong><span>potentially reachable</span></div>
                      <div className="asset-counts">
                        {assetCounts.map(([type, count]) => (
                          <div key={type}><Icon name={type === "database" ? "database" : type === "storage" ? "storage" : "cloud"} /><span>{titleCase(type)}</span><strong>{count}</strong></div>
                        ))}
                      </div>
                      <ul className="asset-list">
                        {blastRadius.data.reachable_assets.map((asset) => (
                          <li key={asset.asset_id}><strong>{asset.name ?? asset.native_identifier ?? asset.asset_id}</strong><span>{titleCase(asset.asset_type)}{asset.region ? ` · ${asset.region}` : ""}</span></li>
                        ))}
                      </ul>
                      <p className="blast-disclaimer">Potential reachability only. These assets were not necessarily accessed.</p>
                    </div>
                  ) : null}
                </div>
              </section>

              <section
                className="investigation-section guidance-section"
                id={INVESTIGATION_SECTIONS.guidance}
                aria-labelledby="guidance-title"
                tabIndex={-1}
              >
                <SectionHeading
                  id="guidance-title"
                  title="Investigation guidance"
                  description="Deterministic next steps, ordered to help an analyst validate and contain this incident."
                />
                <div className="guidance-panel">
                  {guidance.status === "loading" ? <PanelSkeleton rows={4} /> : null}
                  {guidance.status === "error" ? (
                    <PanelError
                      title="Guidance unavailable"
                      message={guidance.message}
                      onRetry={() => setGuidanceReload((value) => value + 1)}
                    />
                  ) : null}
                  {guidance.status === "success" && guidance.data.recommendations.length === 0 ? (
                    <div className="light-empty"><p>No investigation recommendations are available.</p></div>
                  ) : null}
                  {guidance.status === "success" ? (
                    <div className="guidance-list">
                      {guidance.data.recommendations.map((item, index) => (
                        <GuidanceItem key={item.recommendation_id} item={item} order={index + 1} />
                      ))}
                    </div>
                  ) : null}
                </div>
              </section>
            </div>
          </>
        ) : null}
      </main>
    </div>
  );
}
