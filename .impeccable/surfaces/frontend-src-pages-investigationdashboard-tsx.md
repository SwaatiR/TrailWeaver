---
version: 1
slug: "frontend-src-pages-investigationdashboard-tsx"
primary_target: "frontend/src/pages/InvestigationDashboard.tsx"
related_targets: ["frontend/src/styles.css","frontend/src/App.tsx"]
---

Mode: Operate. Audience: cloud security analysts, SOC analysts, and incident responders. Job: move from incident selection to an evidence-safe understanding of sequence, risk, mapped behavior, potential reachability, and next investigative action. The page must consume the M15 API, keep failures local, never expose raw CloudTrail, and never imply potential reachability is observed access.

## Direction contract

THESIS: The incident timeline is the organizing evidence spine; the page refuses the equal-weight grid of interchangeable administration cards. An analyst should understand progression before exploring any secondary analysis.

OWN-WORLD: A slim near-black operations rail borders a warm off-white workspace. Softly bordered 12–16px cards, charcoal typography, restrained semantic severity, and a single electric lime evidence accent form a precise enterprise-security system. One charcoal investigation surface provides focus without turning the product into dark mode.

STORY: The analyst selects a real incident, verifies identity and time scope, reads the chronological signal sequence, understands the deterministic risk total, distinguishes observed ATT&CK mappings from inferred intent, checks cautiously worded reachability, and follows ordered guidance. Empty, loading, unavailable, zero-result, and failed-panel states remain explicit.

FIRST VIEWPORT: At 1536×1024, a roughly 10% navigation rail frames a broad light workspace. The incident heading and metadata lead above four compact summary cards and segmented section navigation. A dark timeline owns about three fifths of the investigation row; guidance occupies the right third. Risk, ATT&CK, and reachability form a compact lower analysis row. Graph appears only as a disabled M17 destination.

FORM: Timeline-dominant investigation workspace, the approved first variant from the user’s comp-first round. Seed key: 08c94370. Approved composition: .impeccable/mocks/m16-investigation-dashboard/timeline-dominant-v2.png.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
