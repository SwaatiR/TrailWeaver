import { useEffect, useMemo, useState } from "react";
import { ApiError, apiBaseUrl, trailWeaverApi } from "../api/client";
import { Icon, type IconName } from "../components/Icon";
import { PanelError, PanelSkeleton } from "../components/StatusViews";
import type {
  BlastRadiusResponse,
  GuidanceResponse,
  IncidentDetail,
  IncidentSummary,
  MitreResponse,
  Recommendation,
  RiskResponse,
} from "../types/api";

type Loadable<T> =
  | { status: "idle" | "loading" }
  | { status: "success"; data: T }
  | { status: "error"; message: string };

type BackendStatus = "checking" | "online" | "offline";

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

export function InvestigationDashboard() {
  const [incidents, setIncidents] = useState<Loadable<IncidentSummary[]>>(loading());
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Loadable<IncidentDetail>>(idle());
  const [risk, setRisk] = useState<Loadable<RiskResponse>>(idle());
  const [mitre, setMitre] = useState<Loadable<MitreResponse>>(idle());
  const [blastRadius, setBlastRadius] = useState<Loadable<BlastRadiusResponse>>(idle());
  const [guidance, setGuidance] = useState<Loadable<GuidanceResponse>>(idle());
  const [backendStatus, setBackendStatus] = useState<BackendStatus>("checking");
  const [listReload, setListReload] = useState(0);
  const [detailReload, setDetailReload] = useState(0);
  const [riskReload, setRiskReload] = useState(0);
  const [mitreReload, setMitreReload] = useState(0);
  const [blastReload, setBlastReload] = useState(0);
  const [guidanceReload, setGuidanceReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setIncidents(loading());
    setBackendStatus("checking");

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
        setIncidents({ status: "success", data: items });
        setSelectedIncidentId((current) => {
          if (current && items.some((item) => item.incident_id === current)) {
            return current;
          }
          return items[0]?.incident_id ?? null;
        });
      })
      .catch((error: unknown) => {
        if (!(error instanceof Error && error.name === "AbortError")) {
          setIncidents({ status: "error", message: errorMessage(error) });
          setSelectedIncidentId(null);
        }
      });

    return () => controller.abort();
  }, [listReload]);

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

  const selectedSummary = useMemo(() => {
    if (incidents.status !== "success") return undefined;
    return incidents.data.find((item) => item.incident_id === selectedIncidentId);
  }, [incidents, selectedIncidentId]);

  const sortedTimeline = useMemo(() => {
    if (detail.status !== "success") return [];
    return [...detail.data.timeline].sort(
      (left, right) =>
        new Date(left.timestamp).valueOf() - new Date(right.timestamp).valueOf(),
    );
  }, [detail]);

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
      <a className="skip-link" href="#workspace-content">Skip to investigation</a>
      <aside className="sidebar" aria-label="TrailWeaver navigation">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true"><i /><i /><i /></span>
          <span>TrailWeaver</span>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <a href="#overview"><Icon name="overview" />Overview</a>
          <a className="primary-nav__item--active" href="#timeline" aria-current="page">
            <Icon name="incident" />Incidents
          </a>
          <a href="#guidance"><Icon name="search" />Investigations</a>
          <a href="#blast"><Icon name="cloud" />Cloud Context</a>
          <button type="button" disabled aria-label="Settings, unavailable in milestone 16">
            <Icon name="settings" />Settings
          </button>
        </nav>

        <section className="incident-queue" aria-labelledby="incident-queue-title">
          <div className="incident-queue__header">
            <h2 id="incident-queue-title">Incident queue</h2>
            {incidents.status === "success" ? <span>{incidents.data.length}</span> : null}
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
                    aria-pressed={selected}
                    onClick={() => setSelectedIncidentId(incident.incident_id)}
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
        </section>

        <div className="sidebar-profile">
          <span aria-hidden="true">TW</span>
          <div><strong>Local analyst</strong><small>Investigation workspace</small></div>
        </div>
      </aside>

      <main className="workspace" id="workspace-content" tabIndex={-1}>
        <header className="workspace-toolbar">
          <nav className="breadcrumb" aria-label="Breadcrumb">
            <span>Incidents</span><b aria-hidden="true">/</b>{selectedIncidentId ?? "No selection"}
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

        {incidents.status === "success" && incidents.data.length === 0 ? (
          <section className="empty-workspace">
            <span className="empty-workspace__icon"><Icon name="shield" /></span>
            <p className="empty-workspace__kicker">Investigation workspace</p>
            <h1>No correlated incidents to investigate</h1>
            <p>
              TrailWeaver is connected to <code>{apiBaseUrl}</code>. Once the security engine
              produces an incident, its deterministic timeline and analyses will appear here.
            </p>
          </section>
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

        {selectedIncidentId ? (
          <>
            <div className="investigation-flow">
              <section
                className="investigation-section incident-section"
                id="overview"
                aria-labelledby="incident-title"
                tabIndex={-1}
              >
                <header className="incident-header">
                  <p className="incident-header__lead">Investigating</p>
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
                  <a href="#overview">Incident</a>
                  <a href="#timeline">Timeline</a>
                  <a href="#analysis">Risk + ATT&amp;CK</a>
                  <button type="button" disabled aria-label="Graph, planned for milestone 17">
                    Graph <span>M17</span>
                  </button>
                  <a href="#blast">Potential impact</a>
                  <a href="#guidance">Guidance</a>
                </nav>

              <section
                className="timeline-panel"
                id="timeline"
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
                        <li key={`${entry.rule_id}-${entry.timestamp}`}>
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
              </section>

              <section
                className="investigation-section meaning-section"
                id="analysis"
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
                className="investigation-section impact-section"
                id="blast"
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
                id="guidance"
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
