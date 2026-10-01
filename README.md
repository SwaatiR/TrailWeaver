# TrailWeaver

TrailWeaver is an AWS-focused cloud security detection and incident reconstruction
platform. It is intended to turn AWS CloudTrail activity into clear, explainable
security investigations.

## The problem

CloudTrail provides detailed records of AWS API activity, but an investigation often
requires analysts to interpret a large volume of low-level events, connect actions
performed across identities and resources, and reconstruct what happened in the right
order. Individual suspicious events may be easy to miss, while the security impact of a
sequence of otherwise ordinary actions can be difficult to assess.

TrailWeaver aims to close that gap by normalizing cloud activity, detecting suspicious
behavior, correlating related evidence, and presenting an explainable account of an
incident and its potential impact.

## Long-term architecture

The planned system is organized into four product layers:

1. **Data:** ingest CloudTrail activity and translate AWS-specific records into a clean
   internal event model.
2. **Security intelligence:** apply deterministic detections, generate signals, correlate
   related behavior, and form incidents.
3. **Investigation:** reconstruct timelines, calculate explainable risk, map behavior to
   MITRE ATT&CK, build identity-resource attack graphs, and estimate blast radius.
4. **User experience:** expose investigation data through an API and dashboard, including
   attack replay and investigation guidance.

Tests, delivery automation, infrastructure, deployment, and monitoring will support
those layers as the project matures.

## Development philosophy

TrailWeaver will grow through small, explicit milestones. Each milestone should add the
simplest readable design that meets the current need. Security conclusions should be
deterministic, testable, and explainable. AWS-specific parsing should remain separate
from the normalized domain model, and dependencies or infrastructure should be added
only when a milestone requires them.

## Current status

**M16: Investigation dashboard** is complete. A React and TypeScript dashboard consumes
the M15 FastAPI endpoints and presents real incident data as a timeline-dominant analyst
workspace. It includes incident selection, deterministic risk factors, observed MITRE
ATT&CK mappings, investigation guidance, and carefully qualified blast-radius context.
Loading, empty, unavailable, zero-result, and panel-level API error states are explicit.

The dashboard never ships fallback incident or analysis fixtures. Its incident titles,
actors, timestamps, signals, risk factors, ATT&CK techniques, guidance, and reachable
assets all come from the configured API. The default development API still starts with
an empty in-memory incident source, so an embedding application must inject incidents
and optional `CloudContext` to populate the dashboard.

M16 does not add persistence, live AWS access, authentication, or background work. M16
leaves the Graph destination disabled and renders no attack replay.

**M17: Interactive attack graph visualization** is complete. The Graph destination is
now an active investigation view within the selected incident. It renders the
`GET /api/v1/incidents/{incident_id}/graph` response directly — no graph is rebuilt in
the browser — with pan, zoom, fit-to-view, reset, type-distinguished nodes, readable
relationship labels, and a node/edge inspector. Analysts move between Overview and
Graph without losing incident selection, and the deterministic initial layout places
the same graph identically on every load.

Graph semantics are observed relationships only: who performed the activity, where it
originated, which identities, roles, and resources appear in the incident evidence,
how those entities connect, which signal produced each relationship, and when each
relationship was observed. Selecting a node shows only data returned by the backend
(type, label, provider, and available account/region/ARN context). Selecting an edge
shows its canonical relationship, observed timestamp, and signal reference. The
incident timeline and graph expose the same stable signal identity, so evidence is
joined explicitly rather than inferred from matching timestamps.

The attack graph must not be confused with blast radius. The graph contains entities
and relationships observed in the incident; blast radius estimates potentially
reachable known assets from explicit permission grants in the loaded cloud context.
Reachable assets are never added to the graph, and no edge implies access beyond what
the evidence supports.

**M18: Temporal Attack Replay** is complete. The Graph workspace retains the complete
M17 Full Graph and adds a Replay mode that reconstructs the observed incident sequence
from the existing incident timeline and graph responses. Each timeline observation is
linked by `signal_id` to zero, one, or multiple graph relationships. This keeps
same-timestamp signals distinguishable and lets missing linkage degrade honestly
without guessing.

Replay steps are ordered deterministically by timestamp, then stable signal identity.
Analysts can move directly between evidence markers, use Previous and Next, run or
pause restrained automatic playback, and restart at the first observation. The graph
is cumulative: earlier observed relationships remain visible as later evidence is
reached, while relationships introduced by the current step receive restrained
emphasis. Node positions and self-loop geometry are computed from the full observed
graph and remain stable throughout playback.

Full Graph and Replay preserve separate responsibilities:

- Full Graph shows every observed relationship returned for the incident.
- Replay reveals evidence-linked observed relationships chronologically.
- Potential impact remains blast-radius context over known assets and is never animated
  into the observed graph.

Replay reconstructs existing observed evidence. It does not predict attacker behavior,
invent intermediary activity, claim that potentially reachable assets were accessed,
or use AI-generated inference. Its state is deterministic presentation logic over data
that is already loaded; stepping does not make additional API requests.

The underlying M13 blast-radius foundation keeps provider-neutral representations and
analysis deliberately separate:

- `AttackGraph` represents relationships observed in suspicious incident activity.
- `CloudContext` represents assets and permission facts known to exist in the cloud
  environment.
- `BlastRadiusAnalyzer` combines an incident's primary identity with explicit grants in
  `CloudContext` to estimate which known assets are potentially reachable.

Cloud assets and their identifiers are deterministic, permission effects are limited to
`allow` and `deny`, and context collections are immutable and canonically ordered.
Blast-radius results preserve the effective allow grants that explain each estimate.
They do not depend on or merge with `AttackGraph`.

Blast radius means potential reachability over the assets loaded in TrailWeaver's known
`CloudContext`. It is not a complete AWS IAM authorization answer. Evaluation uses only
explicit `PermissionGrant` objects: resources match exact asset IDs, and a literal `*`
resource means every asset currently loaded in that context—not every resource that may
exist in AWS. Subject selection prefers the primary actor's ARN, then uses a deterministic
provider/account-scoped identity ID for an actor identifier or name. A deny overrides an
allow only when subject, action scope, and resource scope are exactly the same.
TrailWeaver does not parse policy documents, interpret ARN patterns or conditions, or
evaluate IAM precedence beyond this narrow rule.

Cloud context can be constructed directly from in-memory objects or loaded with
`load_cloud_context` from a strict TrailWeaver-owned JSON fixture:

```json
{
  "assets": [
    {
      "asset_type": "role",
      "provider": "aws",
      "account_id": "123456789012",
      "name": "DeploymentRole",
      "arn": "arn:aws:iam::123456789012:role/DeploymentRole",
      "metadata": {"environment": "production"}
    }
  ],
  "permissions": [
    {
      "subject": "arn:aws:iam::123456789012:role/DeploymentRole",
      "actions": ["*"],
      "resources": ["*"],
      "effect": "allow",
      "source": "attached_managed_policy:arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ]
}
```

The fixture is not an AWS IAM policy-document format and loading it performs no AWS or
network calls. Wildcards remain explicit permission facts and never imply that every
real cloud resource is known or reachable.

For CloudTrail events, the parser reports `failure` when `errorCode` is present and
`success` otherwise. Response fields do not independently determine the outcome. Events
constructed without a provider result use `unknown`.

The security attribute map is deliberately narrow. It currently supports `mfa_used`,
`target_user`, `target_role`, `policy_arn`, and `trail_name` for selected actions. Other
request parameters remain available only as raw evidence and are not copied into the
normalized security context.

## Development setup

TrailWeaver requires Python 3.11 or newer. Create and activate a virtual environment,
then install the package with its development tools:

```bash
python -m pip install -e ".[dev]"
```

Run the project checks with:

```bash
pytest
ruff check .
```

Run the local development API from the repository root with:

```bash
uvicorn trailweaver.api.app:app --reload
```

This normal entry point intentionally starts with an empty incident repository. For
local dashboard development and presentations, start the explicit M16.1 demo entry
point instead:

```bash
uvicorn trailweaver.api.demo:app --reload
```

Demo mode constructs one deterministic AWS account-compromise scenario through the real
detection, correlation, incident, risk, MITRE ATT&CK, blast-radius, and investigation
guidance components. It includes five known demo assets across storage, compute,
database, and secret categories. Reachability is potential reachability over that loaded
demo context; it does not claim any asset was accessed. Demo mode is local
development/presentation support only: it adds no persistence or AWS access and is never
enabled by the normal application entry point.

In a second terminal, start the dashboard with the existing frontend dependencies:

```bash
cd frontend
npm run dev
```

The frontend uses `http://localhost:8000` by default. To point it at another API, copy
`frontend/.env.example` to `frontend/.env` and set:

```dotenv
VITE_TRAILWEAVER_API_URL=http://localhost:8000
```

The API allows `http://localhost:5173` by default. Configure additional explicit
frontend origins as a comma-separated list; wildcard origins are rejected:

```bash
TRAILWEAVER_CORS_ORIGINS=https://dashboard.example,https://analyst.example \
  uvicorn trailweaver.api.app:app --reload
```

Build the production frontend bundle with:

```bash
cd frontend
npm run build
```

The API currently provides:

- `GET /health`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `GET /api/v1/incidents/{incident_id}/risk`
- `GET /api/v1/incidents/{incident_id}/mitre`
- `GET /api/v1/incidents/{incident_id}/graph`
- `GET /api/v1/incidents/{incident_id}/blast-radius`
- `GET /api/v1/incidents/{incident_id}/guidance`

The default development application starts with an empty in-memory incident source.
Applications embedding TrailWeaver can inject existing `Incident` objects and a known
cloud context through `create_app`.

### M19: Persistent investigation repository

TrailWeaver provides an opt-in `SQLiteIncidentRepository` for retaining complete
normalized incident evidence across process restarts. It stores incident and
correlation metadata plus ordered signals and the normalized event fields required to
reconstruct the existing investigation API. Signal IDs, event IDs, enums, and
timezone-aware timestamps are preserved. `raw_event` payloads are intentionally not
copied into this repository; source-record ownership is deferred to M20. SQLite uses
the standard library and an explicit schema version (`PRAGMA user_version`); a new
database initializes automatically, compatible files reopen safely, and unknown or
unversioned schemas fail without destructive replacement.

Risk, MITRE ATT&CK, the observed attack graph, and investigation guidance remain
deterministic derived views of the stored incident evidence. `CloudContext` is
separate external context and is not stored inside incidents. Blast-radius results
therefore remain unavailable unless an application separately supplies the relevant
cloud context. The repository uses insert-only saves: saving a duplicate incident ID
raises `IncidentAlreadyExistsError` rather than replacing evidence. Incidents are
listed in insertion order.

Persistence is explicitly configured; importing the normal application still creates
no database and it remains empty by default. For an embedding runtime that has
persisted incidents, construct its read API with `create_persistent_app`:

```python
from trailweaver.api.app import create_persistent_app

app = create_persistent_app("/var/lib/trailweaver/incidents.sqlite3")
```

The caller controls the database file path; the repository creates its parent
directory and schema when explicitly constructed. The demo application remains
isolated and in-memory. M19 adds persistence only; it does not add CloudTrail
ingestion, upload endpoints, or a public incident-write API.

### M20: Real CloudTrail file ingestion

TrailWeaver accepts standard AWS CloudTrail JSON exports with a strict top-level
`{"Records": [...]}` envelope. JSON arrays and other arbitrary JSON shapes are not
treated as exports. Text, UTF-8 bytes, already-decoded documents, and individual files
can use the same ingestion semantics through `ingest_cloudtrail_json`,
`ingest_cloudtrail_document`, and `ingest_cloudtrail_file`.

Each object in `Records` is passed to the existing `parse_cloudtrail_event` parser;
ingestion does not duplicate AWS normalization rules. A bad individual record produces
a structured, index-addressed issue while other records continue. Results report total,
accepted, failed, and duplicate counts alongside an immutable tuple of normalized events.
An empty `Records` array is a valid zero-event result.

Within one ingestion operation, the first successfully parsed event with a given
non-empty `event_id` wins. Later records with that ID are reported as duplicates rather
than parser failures. Events without IDs are retained and are not falsely deduplicated.
This is deliberately not cross-file or database-backed deduplication. Accepted events
remain in source order, including when timestamps are non-chronological or records in
between fail.

```python
from trailweaver.cloudtrail_ingestion import ingest_cloudtrail_file

result = ingest_cloudtrail_file("export.json", source_label="analyst-upload-42")
print(result.total_records, result.accepted_records)
for issue in result.issues:
    print(issue.record_index, issue.code, issue.event_id)
```

Raw text, bytes, and files have a configurable 10 MiB default size limit. Files are
opened read-only, decoded strictly as UTF-8, and given basename-only provenance unless
the caller supplies a logical label. No separate record-count limit is imposed in M20:
the byte boundary already caps raw inputs, and transports that provide pre-decoded JSON
must enforce their own body limit before decoding. Provenance stays on the ingestion
result rather than entering provider-neutral `NormalizedEvent` objects.

The parser's existing `raw_event` preservation remains unchanged inside accepted
normalized events. Diagnostics do not copy raw records, the investigation API does not
expose them, and M19 incident persistence still does not store them. M20 stops after
normalization: it does not run detection or correlation, create incidents, persist
ingestion results, expose an upload endpoint, or connect to live AWS services.

### M21: End-to-end investigation execution pipeline

`InvestigationRunner` is the explicit synchronous application workflow that connects
the existing stages without reimplementing any of them:

```text
CloudTrail export -> M20 ingestion -> normalized events -> AWS detections
                  -> AWS correlations -> incident creation -> incident repository
                  -> existing read API and dashboard
```

Callers can inject the detection engine, correlation engine, incident factory, and any
`IncidentRepository` implementation directly. The canonical configuration is available
through `create_default_investigation_runner(repository)`, which creates fresh engines
from `AWS_RULES` and `AWS_CORRELATION_RULES`:

```python
from trailweaver.api.execution import create_default_investigation_runner
from trailweaver.api.sqlite_repository import SQLiteIncidentRepository

repository = SQLiteIncidentRepository("investigations.sqlite3")
runner = create_default_investigation_runner(repository)
result = runner.run_cloudtrail_file("export.json", source_label="analyst-upload-42")
print(result.analyzed_event_count, result.signal_count, result.incident_count)
```

The complete M20 result is retained in the execution result, including partial-ingestion
failures and duplicate diagnostics. Successfully accepted events continue through
analysis. An accepted event that matches no detection remains a successfully analyzed
event; a valid signal that does not complete a correlation remains a reported signal;
and zero incidents is a successful pipeline result.

M20 continues to preserve source order. M21 creates a separate analysis ordering by
event timestamp, retaining original source position for equal timestamps. Detection
runs once per event in that order and preserves rule-pack order. The existing
correlation engine receives the resulting signal batch and remains authoritative for
sequence windows, actor matching, and signal reuse.

Generated incidents are saved sequentially through the repository contract. Each
successful save is durable according to that repository, but the contract has no atomic
multi-incident transaction: if a later save fails, earlier saves remain and subsequent
incidents are not attempted. Repository failures propagate and are never reported as a
successful execution.

Reprocessing is **not idempotent in M21**. CloudTrail event IDs are source-provided, but
the existing `Signal`, `CorrelationMatch`, and `Incident` models generate new UUID4
identities on each execution. Running the same source twice therefore normally creates
and persists a second independently identified incident. An
`IncidentAlreadyExistsError` is not treated as prior successful processing because a
random ID collision does not prove evidence equivalence. M21 does not add a file-hash,
processed-source table, or replacement identity scheme.

This pipeline is an in-process application primitive, not production-scale ingestion.
It adds no POST/upload endpoint, frontend upload flow, live AWS access, background jobs,
source-event persistence, or cloud-context discovery. `CloudContext` remains separately
injected into the existing read/analysis service when blast-radius analysis is desired.

## Dashboard behavior and limits

- Incident analyses load independently so one failed endpoint does not erase successful
  timeline, risk, ATT&CK, blast-radius, or guidance data from the other panels.
- “Cloud context unavailable” means blast-radius analysis could not run. “No known
  reachable assets identified” means context was loaded and analysis completed with a
  valid zero result. Neither state is evidence that no real AWS resources are reachable.
- Reachability describes potential access over loaded, known assets; it never represents
  observed access. ATT&CK mappings describe observed behavior and are not proof of intent.
- The dashboard does not expose raw CloudTrail payloads.
