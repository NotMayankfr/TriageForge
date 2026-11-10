output "ec2_public_ip" {
  description = "Public IPv4 address of the TriageForge EC2 instance"
  value       = aws_instance.forge_server.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS of the TriageForge EC2 instance"
  value       = aws_instance.forge_server.public_dns
}

output "security_group_id" {
  description = "Security Group ID for fault testing"
  value       = aws_security_group.forge_sg.id
}

output "route_table_id" {
  description = "Public Route Table ID"
  value       = aws_route_table.forge_public_rt.id
}

output "s3_bucket_name" {
  description = "Target S3 bucket name"
  value       = aws_s3_bucket.forge_bucket.id
}

output "diagnose_command" {
  description = "Ready-to-run TriageForge diagnosis command"
  value       = "triageforge diagnose --url http://${aws_instance.forge_server.public_ip}:80 --aws-sg ${aws_security_group.forge_sg.id} --aws-rt ${aws_route_table.forge_public_rt.id} --aws-instance ${aws_instance.forge_server.id}"
}
