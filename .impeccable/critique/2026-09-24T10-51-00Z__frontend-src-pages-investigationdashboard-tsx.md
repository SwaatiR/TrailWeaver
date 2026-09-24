---
target: implemented M16 investigation dashboard against approved timeline-dominant composition
total_score: 24
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/swaatir/TrailWeaver/frontend/src/pages/InvestigationDashboard.tsx"
target_fingerprint: "sha256:eeedaebc2dd9fb76921f831bfc415d17682b5284675b4b68ed49452a8731aa84"
target_path: /home/swaatir/TrailWeaver/frontend/src/pages/InvestigationDashboard.tsx
timestamp: 2026-09-24T10-51-00Z
slug: frontend-src-pages-investigationdashboard-tsx
---
# Impeccable critique — pre-polish M16

Method: dual-agent (A: `/root/m16_design_assessment` · B: `/root/m16_detector_assessment`)

## Design Health Score

| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 3 | Loading and local states are strong; shared retries destabilize successful panels. |
| 2 | Match System / Real World | 2 | Security concepts fit, but raw rule namespaces and “Sequence complete” are system-centric. |
| 3 | User Control and Freedom | 2 | Selection and retries exist; apparent filters and arrows do not act. |
| 4 | Consistency and Standards | 3 | Cohesive components; some controls promise behavior they lack. |
| 5 | Error Prevention | 3 | Epistemic caveats are excellent; completion language can overstate certainty. |
| 6 | Recognition Rather Than Recall | 3 | Context stays visible; clipped microcopy conceals evidence. |
| 7 | Flexibility and Efficiency | 1 | No long-incident navigation/filtering or panel-specific recovery. |
| 8 | Aesthetic and Minimalist Design | 3 | Strong timeline focus; tiny type and nested scrolling make density feel compressed. |
| 9 | Error Recovery | 2 | Recovery exists, but every panel retry reloads all analyses. |
| 10 | Help and Documentation | 2 | Rationale and caveats help; rule IDs and unfamiliar terms lack contextual explanation. |
| **Total** | | **24/40** | **Acceptable** |

## Design Specificity Verdict

The dark evidence spine, explainable risk, observed ATT&CK language, and cautious reachability treatment feel authored for TrailWeaver rather than interchangeable admin UI. Specificity weakens where API-shaped titles, generic mini-cards, very small utility type, and inert arrow/filter affordances replace an analyst-oriented narrative.

The deterministic detector found **0 issues** in `frontend/src/pages/InvestigationDashboard.tsx`. That clean scan does not contradict the design review: its gaps are runtime/content-length, interaction semantics, contrast, and visual-fidelity issues outside the detector’s rule set. Browser overlay injection was unavailable because both fresh-tab attempts failed closed at the localhost security gate; no user-visible overlay was claimed. Static comp and success-state captures supplied the visual fallback.

## Overall Impression

The page has the right evidence-first composition and a credible enterprise-security world. The biggest opportunity is to let real, variable evidence remain fully readable and recoverable without sacrificing the approved first-viewport hierarchy.

## What’s Working

1. The timeline unmistakably owns the page and establishes an evidence-first reading order.
2. “Observed behavior—not proof of intent” and “Potential reachability—not observed access” preserve analyst trust.
3. The palette, focus styling, reduced-motion handling, disabled M17 destination, and explicit unavailable-versus-zero states form a solid base.

## Priority Issues

### [P1] Variable evidence can be silently clipped

**Why it matters:** The fixed 477px timeline with `overflow:hidden`, fixed lower panels, and `slice(0, 4)` on reachable assets can hide material evidence.

**Fix:** Use content-driven growth or an explicit bounded event scroller with a visible scrollbar. Render all assets or provide an explicit disclosure.

**Suggested command:** `$impeccable harden`, then `$impeccable adapt`.

### [P1] A local retry reloads every analysis

**Why it matters:** One failed endpoint can throw all successful panels back into loading, undermining the promised local failure model.

**Fix:** Give each surface an independent retry trigger and label the failed panel specifically.

**Suggested command:** `$impeccable harden`.

### [P1] Evidence copy can overstate certainty

**Why it matters:** Raw API-shaped titles are secondary evidence, not the narrative; “Sequence complete” implies more than the returned array proves.

**Fix:** Change the ending to “End of observed sequence” and keep rule IDs subordinate.

**Suggested command:** `$impeccable clarify`.

### [P2] Operational typography is too compressed

**Why it matters:** Several 7–11px details and faint tokens fall below a comfortable reading and contrast floor; the distorted “Investigating” treatment is not faithful to the comp.

**Fix:** Raise the detail floor, darken faint text, and remove transform-based faux condensation.

**Suggested command:** `$impeccable audit`, then `$impeccable typeset`.

### [P2] Some affordances promise interactions that do not exist

**Why it matters:** “All signals” looks like a filter and guidance arrows imply navigation.

**Fix:** Render a factual count and remove nonfunctional arrows.

**Suggested command:** `$impeccable distill`, then `$impeccable polish`.

## Persona Red Flags

**Alex, power user:** long evidence can disappear; retries are global; no queue filtering; guidance looks actionable but is inert.

**Sam, accessibility-dependent:** microtype and contrast, fixed-height clipping at zoom, smooth-scroll buttons that do not move focus, and repeated alerts create barriers.

**Riley, stress tester:** fourth-plus timeline events and fifth-plus assets can be hidden; long rationale is ellipsized; mixed success/failure states are unstable.

## Minor Observations

- The comp’s nonfunctional search and notification chrome was correctly omitted.
- The breadcrumb should be semantic navigation.
- The loading shell could more closely mirror the final hierarchy.
- Disabled Settings should not rely on `title` alone.

## Questions to Consider

1. If the timeline is TrailWeaver’s evidence spine, why is it allowed to hide evidence to preserve a 477px composition?
2. Can the API truly prove “Sequence complete,” or only that the returned observed-signal array has ended?
3. Is the section strip navigation, filtering, or a table of contents—and can an analyst accurately predict every item before clicking?

Questions skipped: 5 priority issues were found, but the current request already fixes the answers—address all unfinished M16 issues, preserve the approved timeline-dominant direction, and exclude M17 or attack-graph work.
