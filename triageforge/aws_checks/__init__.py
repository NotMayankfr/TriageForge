"""
AWS Diagnostic Modules for TriageForge
Provides optional AWS infrastructure inspection: Security Groups, Route Tables,
EC2 Status Checks, and CloudWatch Metrics.
Safely falls back or skips if AWS credentials / mode is inactive.
"""

from triageforge.aws_checks.sg_checks import check_security_group
from triageforge.aws_checks.route_checks import check_route_table_igw
from triageforge.aws_checks.cloudwatch_checks import check_ec2_cpu_alarm

__all__ = ["check_security_group", "check_route_table_igw", "check_ec2_cpu_alarm"]
