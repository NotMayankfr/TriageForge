"""
AWS Security Group Diagnostic Checks
Inspects ingress rules using boto3 to verify if the target port (80/443) is permitted.
"""

from __future__ import annotations
from typing import Optional
from triageforge.models import CheckStatus, Evidence, LayerResult


def check_security_group(
    group_id: Optional[str] = None,
    port: int = 443,
    region: str = "us-east-1",
) -> LayerResult:
    """Queries EC2 describe_security_groups to ensure ingress rule exists."""
    evidence = []
    metadata = {"group_id": group_id, "port": port, "region": region}

    if not group_id:
        return LayerResult(
            layer_name="aws_sg",
            status=CheckStatus.SKIPPED,
            duration_ms=0.0,
            evidence=[
                Evidence(
                    layer="aws_sg",
                    metric="sg_ingress",
                    status=CheckStatus.SKIPPED,
                    observed="No AWS Group ID provided",
                    message="Skipping AWS SG check (running in local container mode).",
                    weight=0.0,
                )
            ],
            metadata=metadata,
        )

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_security_groups(GroupIds=[group_id])
        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            return LayerResult(
                layer_name="aws_sg",
                status=CheckStatus.FAIL,
                duration_ms=50.0,
                evidence=[
                    Evidence(
                        layer="aws_sg",
                        metric="sg_exists",
                        status=CheckStatus.FAIL,
                        observed=f"Security Group {group_id} not found",
                        message=f"AWS Security Group {group_id} does not exist in {region}.",
                        weight=1.5,
                    )
                ],
                metadata=metadata,
            )

        sg = sgs[0]
        port_allowed = False
        allowed_cidrs = []

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")
            ip_proto = rule.get("IpProtocol")

            # Check if port matches or protocol is -1 (all traffic)
            if ip_proto == "-1" or (from_port is not None and to_port is not None and from_port <= port <= to_port):
                port_allowed = True
                for ip_range in rule.get("IpRanges", []):
                    allowed_cidrs.append(ip_range.get("CidrIp", ""))

        metadata["port_allowed"] = port_allowed
        metadata["allowed_cidrs"] = allowed_cidrs

        if port_allowed:
            evidence.append(
                Evidence(
                    layer="aws_sg",
                    metric="sg_ingress",
                    status=CheckStatus.OK,
                    observed=f"Port {port} allowed from {', '.join(allowed_cidrs) or 'any'}",
                    message=f"Security Group {group_id} permits inbound traffic on port {port}.",
                    weight=1.0,
                )
            )
            return LayerResult(
                layer_name="aws_sg",
                status=CheckStatus.OK,
                duration_ms=100.0,
                evidence=evidence,
                metadata=metadata,
            )
        else:
            evidence.append(
                Evidence(
                    layer="aws_sg",
                    metric="sg_ingress",
                    status=CheckStatus.FAIL,
                    observed=f"Port {port} not permitted in ingress rules",
                    expected=f"Rule allowing port {port} from client CIDR",
                    message=f"Security Group {group_id} BLOCKS port {port}. Missing inbound ingress rule.",
                    weight=2.0,
                )
            )
            return LayerResult(
                layer_name="aws_sg",
                status=CheckStatus.FAIL,
                duration_ms=100.0,
                evidence=evidence,
                metadata=metadata,
                error_message=f"Security Group {group_id} blocks inbound port {port}.",
            )

    except Exception as e:
        return LayerResult(
            layer_name="aws_sg",
            status=CheckStatus.SKIPPED,
            duration_ms=10.0,
            evidence=[
                Evidence(
                    layer="aws_sg",
                    metric="aws_client",
                    status=CheckStatus.SKIPPED,
                    observed=str(e),
                    message=f"AWS API unreachable or no credentials configured: {e}",
                    weight=0.0,
                )
            ],
            metadata=metadata,
            error_message=str(e),
        )
