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

**M6: Initial AWS detection pack** is complete. TrailWeaver now detects successful
console logins without MFA, attachment of the AWS managed AdministratorAccess policy,
IAM access-key creation, and CloudTrail logging being stopped. The pack is an explicit
tuple of rules consumed by the stateless detection engine. Correlation, incidents, risk
scoring, persistence, APIs, dashboards, infrastructure, and AWS SDK integration have
not been implemented.

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
