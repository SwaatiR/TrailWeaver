# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users are cloud security analysts, SOC analysts, and incident responders
investigating suspicious AWS activity. The product should also communicate its value
clearly to recruiters, professors, and hackathon audiences without compromising the
depth or precision required by practitioners.

## Product Purpose

TrailWeaver turns low-level AWS CloudTrail activity into transparent, reconstructable
security investigations. It helps analysts understand what happened, how related
actions connect, why an incident matters, what is known versus merely possible, and
which evidence supports each conclusion.

Success means an analyst can move from suspicious cloud activity to a clear incident
narrative and actionable investigation guidance without treating opaque or fabricated
claims as fact.

## Positioning

TrailWeaver provides deterministic and explainable attack reconstruction through a
traceable pipeline:

CloudTrail activity -> normalized security events -> detections -> correlated signals
-> incidents -> risk explanation -> MITRE ATT&CK mapping -> attack graph -> blast-radius
context -> investigation guidance.

TrailWeaver does not aim to replace enterprise detection products such as Amazon
GuardDuty or SIEM platforms. It complements them by making cloud incidents transparent,
reconstructable, and easier to investigate. Its security conclusions remain tied to
explicit rules and evidence rather than opaque AI inference.

## Operating Context

Analysts use TrailWeaver to inspect suspicious AWS identity and resource activity,
follow related events in sequence, understand risk factors and ATT&CK mappings, examine
actor-resource relationships, distinguish observed actions from potential reachability,
and decide what to investigate next.

The product architecture consists of a deterministic security engine, a FastAPI backend,
and a React dashboard. Raw CloudTrail evidence remains internal; the frontend consumes
purpose-built incident and analysis representations rather than exposing raw event
payloads directly.

## Capabilities and Constraints

- AWS is the current product scope.
- Internal domain models should remain provider-neutral where practical.
- Detection, correlation, risk, and other core security logic must be deterministic,
  testable, and explainable, without depending on AI.
- Security conclusions and missing evidence must never be fabricated.
- Observed activity must be clearly distinguished from inferred or potential
  reachability.
- AWS-specific parsing must remain separate from normalized internal models.
- The dashboard must not expose raw CloudTrail evidence directly.
- The system grows through small, explicit milestones; future modules must not be built
  ahead of the requested milestone.
- Credentials, keys, tokens, secrets, and Terraform state must never be committed.

## Brand Commitments

The product name is TrailWeaver. Product language should be precise, evidence-led, and
clear about uncertainty. Security findings must explain what was observed, how a result
was derived, and where the system's knowledge ends.

The dashboard has a binding visual constraint: it should combine a premium modern
enterprise SaaS layout, a slim near-black sidebar, a light or off-white primary
workspace, rounded modular cards, a restrained lime or yellow-green accent, selective
dark investigation surfaces, and clean information density. It must avoid both a
generic admin-template appearance and a neon hacker aesthetic. The user has reference
dashboards that should inform the approved composition before implementation.

## Evidence on Hand

- The repository contains a tested Python security engine covering CloudTrail parsing,
  normalization, deterministic detections, signal correlation, incident generation,
  risk scoring, MITRE ATT&CK mapping, attack graphs, blast-radius analysis, and
  investigation guidance.
- A FastAPI adapter exposes incident and analysis results through versioned JSON
  endpoints.
- The current application uses in-memory incident and cloud-context inputs; persistence,
  live AWS access, authentication, background work, and a frontend are not yet present.
- Reference dashboards exist but have not yet been supplied in the repository or this
  workspace.
- No customer claims, testimonials, production benchmarks, certifications, or deployment
  claims are present. Future product work must not invent them.

## Product Principles

1. Make every security conclusion traceable to explicit evidence and deterministic logic.
2. Reconstruct incidents as coherent sequences, not disconnected alerts.
3. Distinguish observed behavior from possible impact or reachability at every layer.
4. Preserve analyst trust through precise language, visible reasoning, and honest limits.
5. Make sophisticated cloud investigations understandable without flattening their
   technical meaning.
