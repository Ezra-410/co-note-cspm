# =============================================================================
# Network: one VPC, one public subnet (no NAT gateway -> no hourly NAT cost).
# The application host is reachable on HTTP/HTTPS only (intended public
# service). Administration goes through SSM Session Manager, NOT SSH:
# the admin security group has NO inbound rule on purpose.
# =============================================================================
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "conote" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "conote-vpc" }
}

resource "aws_internet_gateway" "conote" {
  vpc_id = aws_vpc.conote.id
  tags   = { Name = "conote-igw" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.conote.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "conote-public-a", Tier = "public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.conote.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.conote.id
  }
  tags = { Name = "conote-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

# CIS: the default security group must not allow any traffic.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.conote.id
  tags   = { Name = "conote-default-sg-locked" }
}

# Intended public exposure: the web front of Co-note.
resource "aws_security_group" "web" {
  name        = "conote-web-sg"
  description = "Co-note web front: HTTP/HTTPS from the internet (intended)"
  vpc_id      = aws_vpc.conote.id
  tags        = { Name = "conote-web-sg", Exposure = "public-intended" }
}

resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id = aws_security_group.web.id
  description       = "HTTP (redirect to HTTPS)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web.id
  description       = "HTTPS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "web_out" {
  security_group_id = aws_security_group.web.id
  description       = "Outbound (package updates, SSM)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# Administrative access group: deliberately EMPTY. The drift simulation adds
# 22/tcp from 0.0.0.0/0 here "by hand" - the CSPM tools must catch it.
resource "aws_security_group" "admin" {
  name        = "conote-admin-sg"
  description = "Co-note admin access - no inbound rules, use SSM Session Manager"
  vpc_id      = aws_vpc.conote.id
  tags        = { Name = "conote-admin-sg", Exposure = "none" }
}

# VPC flow logs -> CloudWatch Logs (network evidence for investigations)
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/conote/vpc-flow-logs"
  retention_in_days = 30
}

resource "aws_iam_role" "flow_logs" {
  name = "conote-vpc-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "write-flow-logs"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "conote" {
  vpc_id          = aws_vpc.conote.id
  traffic_type    = "REJECT"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}
