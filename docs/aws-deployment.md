# AWS deployment runbook

TrailWeaver deploys as one ECS/Fargate task with two containers. The dashboard is the
only load-balanced container and proxies API requests over the task-local loopback
interface. The API mounts encrypted EFS at `/data` for SQLite. ECS uses the task role;
no access key is placed in an image or Terraform variable.

## Prerequisites

- an explicitly selected AWS account and region;
- an existing VPC with at least two application subnets that can reach AWS APIs;
- at least two public load-balancer subnets;
- an ACM certificate valid for the DNS name operators will use;
- an existing private CloudTrail bucket and non-empty key prefix; and
- AWS CLI, Docker, and Terraform authenticated through approved provider chains.

Use specific operator/network CIDRs. Terraform rejects `0.0.0.0/0` for the HTTPS
listener. The application subnets need NAT or suitable VPC endpoints for ECR, Logs,
and S3; the task is not assigned a public IP.

## Build and publish

Choose an immutable release tag, normally the reviewed Git commit SHA. Replace the
shell placeholders explicitly before running commands.

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=111122223333
export RELEASE_TAG=<reviewed-git-sha>

aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin \
  "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker build -t trailweaver-api:"$RELEASE_TAG" .
docker build -t trailweaver-dashboard:"$RELEASE_TAG" frontend

docker tag trailweaver-api:"$RELEASE_TAG" \
  "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/trailweaver-api:$RELEASE_TAG"
docker tag trailweaver-dashboard:"$RELEASE_TAG" \
  "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/trailweaver-dashboard:$RELEASE_TAG"

docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/trailweaver-api:$RELEASE_TAG"
docker push "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/trailweaver-dashboard:$RELEASE_TAG"
```

The account number is fictional. Prefer obtaining the real account identifier from an
approved deployment context rather than storing it in the repository.

## Plan and apply

Create an uncommitted `.tfvars` file or pass values through your deployment system.
Required inputs include the VPC/subnets, restricted ingress CIDRs, ACM certificate,
CloudTrail source, and both immutable image tags.

```bash
cd infra/terraform
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan -out=trailweaver.tfplan
terraform apply trailweaver.tfplan
terraform output application_url
```

Configure a DNS record matching the ACM certificate to alias the load balancer. Verify
`https://<configured-hostname>/health` and then the dashboard/API. The raw load-balancer
hostname output is diagnostic; certificate hostname verification generally requires
the configured DNS name.

## Update and rollback

Push a new immutable pair of images and update both image-tag variables. Fargate stops
the old task before starting the new task so only one SQLite writer exists. This causes
brief downtime. Roll back by restoring the previous two known-good image tags and
applying again.

## Destroy

Review a destroy plan before approval:

```bash
terraform plan -destroy
terraform destroy
```

Deletion protection on the load balancer must be deliberately disabled in Terraform
before destruction. Non-empty immutable ECR repositories also require an explicit
image-retention decision. Back up `/data/incidents.sqlite3` before destroying EFS;
Terraform does not back up application data.

No deployment is performed by repository CI. Operators remain responsible for AWS
change approval, remote-state controls, DNS, certificate validation, backup, and cost.
