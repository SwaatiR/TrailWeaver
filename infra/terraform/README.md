# TrailWeaver AWS foundation

This Terraform root creates the shared AWS resources required by the current
single-instance TrailWeaver architecture. It intentionally accepts an existing VPC,
subnets, and private CloudTrail S3 bucket rather than taking ownership of account-wide
logging or networking.

It creates:

- private, immutable, scan-on-push ECR repositories for the API and dashboard;
- an ECS cluster and retained CloudWatch log group;
- ECS execution and workload roles;
- read-only S3 permissions limited to one bucket and object prefix; and
- encrypted EFS storage, an access point for UID/GID `10001`, and mount targets for
  durable SQLite storage.

The execution role uses AWS's standard `AmazonECSTaskExecutionRolePolicy` for ECR image
pulls and CloudWatch Logs delivery. That managed policy includes the unavoidable
resource wildcard for `ecr:GetAuthorizationToken`, which AWS does not support scoping
to a repository. The application task role is separate and has no wildcard resources;
its S3 access is constrained to the configured bucket and prefix.

M26 does not create an ECS task/service, load balancer, public listener, CloudTrail
trail, or bucket. Deployment resources are layered on this foundation in M27.

## Planning

Use an AWS profile or workload identity from the normal provider chain. Do not place
credentials in Terraform variables.

```bash
cd infra/terraform
terraform init
terraform plan \
  -var='vpc_id=vpc-0123456789abcdef0' \
  -var='application_subnet_ids=["subnet-0123456789abcdef0","subnet-0fedcba9876543210"]' \
  -var='cloudtrail_bucket_name=example-private-cloudtrail' \
  -var='cloudtrail_prefix=AWSLogs/111122223333/CloudTrail'
```

The IDs and names above are fictional. Supply subnets in distinct availability zones.
The application subnets need a controlled route to AWS APIs (normally NAT or VPC
endpoints) because the runtime pulls images, writes logs, and reads S3 over HTTPS.

Terraform uses local state unless the operator configures a backend during `init`.
Local state and variable files are ignored by Git. A team deployment should configure
an encrypted, access-controlled remote backend outside this reusable root and protect
state backups because state contains infrastructure metadata.

SQLite on EFS remains a single-writer, single-task deployment constraint. EFS supplies
durability across task replacement; it does not make SQLite safe for horizontal scale.
