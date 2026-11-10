variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 Instance size (Free tier eligible)"
  type        = string
  default     = "t3.micro"
}

variable "my_ip_cidr" {
  description = "Your workstation IP in CIDR format (e.g. 203.0.113.4/32) for SSH access"
  type        = string
  default     = "0.0.0.0/0"
}
