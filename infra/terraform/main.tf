locals {
  cloudtrail_prefix = trim(var.cloudtrail_prefix, "/")
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_iam_policy_document" "ecs_tasks_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_ecr_repository" "api" {
  name                 = "${var.name_prefix}-api"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "dashboard" {
  name                 = "${var.name_prefix}-dashboard"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "runtime" {
  name              = "/trailweaver/${var.name_prefix}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json
}

data "aws_iam_policy_document" "cloudtrail_read" {
  statement {
    sid       = "ListConfiguredCloudTrailPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.cloudtrail_bucket_name}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        local.cloudtrail_prefix,
        "${local.cloudtrail_prefix}/*",
      ]
    }
  }

  statement {
    sid       = "ReadConfiguredCloudTrailObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.cloudtrail_bucket_name}/${local.cloudtrail_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_read" {
  name   = "cloudtrail-read"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.cloudtrail_read.json
}

resource "aws_security_group" "runtime" {
  name_prefix = "${var.name_prefix}-runtime-"
  description = "TrailWeaver ECS task traffic"
  vpc_id      = var.vpc_id

  egress {
    description = "HTTPS to AWS APIs and dependency endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS over UDP inside the selected VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "DNS over TCP inside the selected VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "NFS to EFS inside the selected VPC"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "efs" {
  name_prefix = "${var.name_prefix}-efs-"
  description = "TrailWeaver EFS mount traffic"
  vpc_id      = var.vpc_id

  ingress {
    description     = "NFS from the TrailWeaver ECS task"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.runtime.id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_efs_file_system" "incidents" {
  encrypted = true

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name = "${var.name_prefix}-incidents"
  }
}

resource "aws_efs_access_point" "incidents" {
  file_system_id = aws_efs_file_system.incidents.id

  posix_user {
    gid = 10001
    uid = 10001
  }

  root_directory {
    path = "/trailweaver"

    creation_info {
      owner_gid   = 10001
      owner_uid   = 10001
      permissions = "0750"
    }
  }
}

resource "aws_efs_mount_target" "incidents" {
  for_each = var.application_subnet_ids

  file_system_id  = aws_efs_file_system.incidents.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}
