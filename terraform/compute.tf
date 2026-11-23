# =============================================================================
# Compute: one small Co-note application host.
#   - IMDSv2 required (blocks SSRF credential theft via the metadata service)
#   - encrypted root volume + EBS encryption by default for the whole region
#   - SSM instead of SSH (no key pair, no port 22)
#   - serves a placeholder Co-note page on HTTP so there is a real public service
# Stop it when you are not working (aws ec2 stop-instances) to save credits.
# =============================================================================
resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_iam_role" "app_host" {
  name = "conote-app-host"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_host_ssm" {
  role       = aws_iam_role.app_host.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app_host" {
  name = "conote-app-host"
  role = aws_iam_role.app_host.name
}

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public_a.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id, aws_security_group.admin.id]
  iam_instance_profile        = aws_iam_instance_profile.app_host.name
  monitoring                  = false

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  user_data = <<-EOT
    #!/bin/bash
    dnf -y install nginx
    echo '<h1>Co-note (lab)</h1><p>CSPM target environment</p>' > /usr/share/nginx/html/index.html
    systemctl enable --now nginx
  EOT

  tags = { Name = "conote-app-01", Role = "app", Exposure = "public-intended" }

  # Never replace the server just because AWS published a newer image:
  # patching is done in place (dnf upgrade via SSM), not by surprise rebuilds.
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  depends_on = [aws_ebs_encryption_by_default.on]
}
