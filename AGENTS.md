# TrailWeaver Engineering Guide

## Engineering rules

- Build incrementally in small milestones.
- Only implement the milestone explicitly requested.
- Do not implement future modules early.
- Use Python type hints.
- Prefer simple, readable designs.
- Keep modules focused and small.
- Avoid premature abstractions.
- Avoid microservices unless there is a real need later.
- Core security detections must be deterministic and explainable.
- Never hard-code AWS credentials or secrets.
- Never commit credentials, keys, tokens, or Terraform state.
- Keep AWS-specific parsing separate from normalized internal models.
- Write tests for meaningful behavior.
- Do not add dependencies unless the current milestone requires them.

## Roadmap

### Layer 1: Data

- CloudTrail ingestion
- Event normalization

### Layer 2: Security Intelligence

- Detection engine
- Signal generation
- Correlation
- Incident generation

### Layer 3: Investigation

- Timeline
- Risk scoring
- MITRE ATT&CK mapping
- Attack graph
- Blast-radius analysis

### Layer 4: User Experience

- API
- Dashboard
- Attack replay
- Investigation explanation

### Engineering layer

- Tests
- Docker
- CI/CD
- Terraform
- AWS deployment
- Monitoring

## Next milestone

The next engineering milestone after project setup is **M1: Normalized event model**.
Do not implement M1 as part of the project setup milestone.

