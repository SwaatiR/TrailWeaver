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

**M13: Blast radius foundation** is complete. TrailWeaver now has deliberately separate
provider-neutral representations and analysis:

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
