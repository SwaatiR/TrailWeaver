# TrailWeaver demo script

Target length: 2–3 minutes. Audience: analysts first, then a brief engineering
overview for reviewers. All screens are the real product: the demo API, the CLI,
and the dashboard. Nothing is mocked.

## Prerequisites

- Python 3.11 or newer, dependencies installed (`python -m pip install -e ".[dev]"`).
- Frontend dependencies installed (`cd frontend && npm install`).
- Two terminals: one for the API, one for the dashboard and CLI.
- Optional: Docker available for the closing architecture beat.

## Asset checklist

Capture each asset from the live demo and save it at the exact path. Never commit
mock, generated, or placeholder images.

| Asset | Source screen | Path |
| ----- | ------------- | ---- |
| Hero image | Investigation dashboard, demo incident selected, Overview visible (identity, timeline, risk, MITRE, guidance) | `docs/assets/trailweaver-overview.png` |
| Investigation result | Same incident, Investigation destination, incident identity, risk score, severity, correlated signals, and ordered incident timeline visible | `docs/assets/investigation-result.png` |
| Attack graph | Same incident, Graph destination, full observed graph fitted to view | `docs/assets/attack-graph.png` |
| Replay loop | Same incident, Replay mode, mid-sequence step with current-step emphasis visible, 5–10 second loop | `docs/assets/temporal-replay.gif` |
| Demo thumbnail | Any of the above at 1280×720, readable at small size | `docs/assets/demo-thumbnail.png` |

Capture at 1280×720 or wider. Use the deterministic demo incident only. Redact or
avoid real account IDs, real ARNs, and real credentials; the demo fixture values are
safe to show.

## Setup (before recording)

```bash
# Terminal 1: deterministic demo API
uvicorn trailweaver.api.demo:app --reload

# Terminal 2: dashboard
cd frontend
npm run dev
```

Open `http://localhost:5173`. Confirm the workspace starts empty with zero
incidents and both analysis initiators visible: file analysis enabled, S3
analysis marked unavailable in the local demo. Upload
`samples/cloudtrail/account-compromise-sequence.json` through the CloudTrail
file card, confirm the Analysis complete result (3 records, 3 accepted,
3 signals, 1 correlation, 1 incident), and open the resulting investigation.
The Overview panels (timeline, risk factors, MITRE ATT&CK, guidance, blast
radius) populate from that analyzed incident before recording. Use the small
Reset demo control to return to the empty workspace and repeat the flow. The
demo also supports the full workflow: History lists the created incident,
Close investigation returns to the Overview without deleting it, and Clear
history only dismisses the History view for the session.

For the CLI beat, have this ready in terminal 2:

```bash
trailweaver --database /tmp/trailweaver-demo.sqlite3 \
  analyze-file samples/cloudtrail/account-compromise-sequence.json
```

## Script

Total budget is about 2 minutes 45 seconds. Keep each beat to one or two sentences.

### 0:00 — CloudTrail evidence (about 20 seconds)

Show `samples/cloudtrail/account-compromise-sequence.json` in an editor. One line:
low-level AWS API records — console login without MFA, access-key creation, an
administrator policy attach — that are hard to assess in isolation.

### 0:20 — CLI analysis (about 20 seconds)

Run the `analyze-file` command above. Point at the stage counts in the output:
source records, accepted records, signals, correlations, created and persisted
incidents. Note that raw payloads are never printed and zero incidents would be a
valid result for benign evidence.

### 0:40 — Incident creation (about 15 seconds)

State the pipeline in one sentence: ingestion, normalized events, deterministic
detections, correlated signals, one incident, persisted to SQLite. Emphasize that
reprocessing generates new identities — it is not idempotent.

### 0:55 — Dashboard overview (about 15 seconds)

Switch to the dashboard, which starts with an empty workspace. Upload the
fixture through the CloudTrail file card, hold the Analysis complete result
for a beat, then open the resulting investigation: identity, timeline, risk,
MITRE, and guidance on one screen. This is the hero framing — hold it for two
beats before scrolling. S3 analysis stays visibly disabled; the small Reset
demo control returns to the empty workspace.

### 1:10 — Timeline, risk, MITRE (about 20 seconds)

Scroll through the timeline in order, then the risk factors and ATT&CK mapping.
One line each: the timeline joins evidence on stable signal identity; risk
explains why it matters; ATT&CK describes observed behavior, not intent.

### 1:30 — Attack graph (about 15 seconds)

Open the Graph destination. Pan once, select one node and one edge to show the
inspector: type, label, provider context, canonical relationship, observed
timestamp, signal reference. State the boundary: observed relationships only.

### 1:45 — Temporal replay (about 15 seconds)

Switch to Replay mode. Step forward twice, then run brief automatic playback.
Narrate: cumulative observed relationships revealed chronologically; positions
stay stable; nothing is predicted and reachable assets are never animated in.

### 2:00 — Blast radius (about 10 seconds)

Return to the blast-radius panel. One line: potential reachability over the five
loaded demo assets from explicit permission grants — never observed access.

### 2:10 — Investigation guidance (about 15 seconds)

Show the guidance panel. One line: deterministic next steps derived from stored
evidence, with honest limits where context is unavailable.

### 2:25 — Docker, CI, Terraform, AWS (about 20 seconds)

Close with one architecture sentence over terminal or diagram, not the dashboard:
two containers (`docker compose up --build`, dashboard on `8080`), CI builds and
tests both images, Terraform deploys one ECS/Fargate task with EFS-backed SQLite
behind an HTTPS load balancer. Point to `docs/aws-deployment.md` and stop.

## After recording

1. Export the thumbnail (`docs/assets/demo-thumbnail.png`) and link the video at
   the top of the README Demo section.
2. Re-check the README narrative order: product, problem, how it works, security
   analysis, run it yourself, engineering and AWS architecture.
3. Confirm no asset is mocked and no real credentials appear in any capture.
