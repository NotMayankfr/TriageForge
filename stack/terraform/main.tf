terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "TriageForge"
      Environment = "Lab"
      ManagedBy   = "Terraform"
      CostCenter  = "Zero-Cost-Free-Tier"
    }
  }
}

# 1. VPC & Public Subnet (Zero NAT Gateway to avoid cost)
resource "aws_vpc" "forge_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "triageforge-vpc"
  }
}

resource "aws_internet_gateway" "forge_igw" {
  vpc_id = aws_vpc.forge_vpc.id

  tags = {
    Name = "triageforge-igw"
  }
}

resource "aws_subnet" "forge_public_subnet" {
  vpc_id                  = aws_vpc.forge_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "triageforge-public-subnet"
  }
}

resource "aws_route_table" "forge_public_rt" {
  vpc_id = aws_vpc.forge_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.forge_igw.id
  }

  tags = {
    Name = "triageforge-public-rt"
  }
}

resource "aws_route_table_association" "forge_public_assoc" {
  subnet_id      = aws_subnet.forge_public_subnet.id
  route_table_id = aws_route_table.forge_public_rt.id
}

# 2. Security Group (Port 22 SSH, Port 80 HTTP, Port 443 HTTPS)
resource "aws_security_group" "forge_sg" {
  name        = "triageforge-instance-sg"
  description = "Controls ingress and egress for TriageForge EC2 lab instance"
  vpc_id      = aws_vpc.forge_vpc.id

  ingress {
    description = "SSH administrative access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }

  ingress {
    description = "HTTP web ingress"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS web ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Unrestricted outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "triageforge-sg"
  }
}

# 3. IAM Role & S3 Bucket
resource "aws_s3_bucket" "forge_bucket" {
  bucket_prefix = "triageforge-assets-"
  force_destroy = true

  tags = {
    Name = "triageforge-assets"
  }
}

resource "aws_iam_role" "forge_instance_role" {
  name = "TriageForgeEC2Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "forge_s3_policy" {
  name        = "TriageForgeS3AccessPolicy"
  description = "Grants read access to the TriageForge S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.forge_bucket.arn,
        "${aws_s3_bucket.forge_bucket.arn}/*"
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "forge_role_attach" {
  role       = aws_iam_role.forge_instance_role.name
  policy_arn = aws_iam_policy.forge_s3_policy.arn
}

resource "aws_iam_instance_profile" "forge_profile" {
  name = "TriageForgeInstanceProfile"
  role = aws_iam_role.forge_instance_role.name
}

# 4. EC2 Instance (Free-tier t3.micro or t4g.small)
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "forge_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.forge_public_subnet.id
  vpc_security_group_ids = [aws_security_group.forge_sg.id]
  iam_instance_profile = aws_iam_instance_profile.forge_profile.name

  root_block_device {
    volume_size           = 12
    volume_type           = "gp3"
    delete_on_termination = true
  }

  user_data = file("${path.module}/user_data.sh")

  tags = {
    Name = "triageforge-lab-host"
  }
}

# 5. CloudWatch CPU Metric Alarm & SNS Topic
resource "aws_sns_topic" "forge_alerts" {
  name = "triageforge-alarms-topic"
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "triageforge-ec2-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggers when TriageForge EC2 CPU exceeds 80% for 2 minutes"
  alarm_actions       = [aws_sns_topic.forge_alerts.arn]

  dimensions = {
    InstanceId = aws_instance.forge_server.id
  }
}
