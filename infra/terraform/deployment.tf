resource "aws_security_group" "load_balancer" {
  name_prefix = "${var.name_prefix}-alb-"
  description = "Restricted HTTPS access to the TrailWeaver dashboard"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from explicitly approved operator networks"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  egress {
    description = "Dashboard traffic to the TrailWeaver task"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "dashboard_from_load_balancer" {
  type                     = "ingress"
  description              = "Dashboard traffic from the application load balancer"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.load_balancer.id
  security_group_id        = aws_security_group.runtime.id
}

resource "aws_lb" "this" {
  name                       = substr("${var.name_prefix}-alb", 0, 32)
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.load_balancer.id]
  subnets                    = var.load_balancer_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "dashboard" {
  name        = substr("${var.name_prefix}-dashboard", 0, 32)
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  deregistration_delay = 15

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/healthz"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dashboard.arn
  }
}

data "aws_iam_policy_document" "efs_client" {
  statement {
    sid    = "MountIncidentStorage"
    effect = "Allow"
    actions = [
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientWrite",
    ]
    resources = [aws_efs_file_system.incidents.arn]

    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.incidents.arn]
    }
  }
}

resource "aws_iam_role_policy" "efs_client" {
  name   = "efs-client"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.efs_client.json
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  volume {
    name = "incidents"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.incidents.id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.incidents.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = "${aws_ecr_repository.api.repository_url}:${var.api_image_tag}"
      essential = true
      portMappings = [{
        containerPort = 8000
        hostPort      = 8000
        protocol      = "tcp"
      }]
      environment = [
        { name = "TRAILWEAVER_DATABASE_PATH", value = "/data/incidents.sqlite3" },
        { name = "TRAILWEAVER_API_HOST", value = "0.0.0.0" },
        { name = "TRAILWEAVER_API_PORT", value = "8000" },
        { name = "TRAILWEAVER_CORS_ORIGINS", value = "" },
        { name = "TRAILWEAVER_LOG_LEVEL", value = "info" },
        { name = "TRAILWEAVER_AWS_REGION", value = var.aws_region },
      ]
      mountPoints = [{
        sourceVolume  = "incidents"
        containerPath = "/data"
        readOnly      = false
      }]
      healthCheck = {
        command = [
          "CMD-SHELL",
          "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)\" || exit 1",
        ]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.runtime.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "api"
        }
      }
    },
    {
      name      = "dashboard"
      image     = "${aws_ecr_repository.dashboard.repository_url}:${var.dashboard_image_tag}"
      essential = true
      dependsOn = [{
        containerName = "api"
        condition     = "HEALTHY"
      }]
      portMappings = [{
        containerPort = 8080
        hostPort      = 8080
        protocol      = "tcp"
      }]
      environment = [
        { name = "TRAILWEAVER_API_UPSTREAM", value = "127.0.0.1:8000" },
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.runtime.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "dashboard"
        }
      }
    },
  ])
}

resource "aws_ecs_service" "this" {
  name            = var.name_prefix
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  health_check_grace_period_seconds  = 60
  enable_execute_command             = false
  wait_for_steady_state              = true

  network_configuration {
    subnets          = var.application_subnet_ids
    security_groups  = [aws_security_group.runtime.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.dashboard.arn
    container_name   = "dashboard"
    container_port   = 8080
  }

  depends_on = [
    aws_efs_mount_target.incidents,
    aws_iam_role_policy.efs_client,
    aws_lb_listener.https,
  ]
}
