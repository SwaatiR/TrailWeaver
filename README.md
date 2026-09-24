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

M16 does not add persistence, live AWS access, authentication, or background work. The
Graph destination is deliberately disabled for M17; M16 does not render attack replay
or an interactive attack graph.

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

## Dashboard behavior and limits

- Incident analyses load independently so one failed endpoint does not erase successful
  timeline, risk, ATT&CK, blast-radius, or guidance data from the other panels.
- “Cloud context unavailable” means blast-radius analysis could not run. “No known
  reachable assets identified” means context was loaded and analysis completed with a
  valid zero result. Neither state is evidence that no real AWS resources are reachable.
- Reachability describes potential access over loaded, known assets; it never represents
  observed access. ATT&CK mappings describe observed behavior and are not proof of intent.
- The dashboard does not expose raw CloudTrail payloads.
