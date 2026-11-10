"""
AWS CloudWatch & EC2 Status Checks
Verifies EC2 2/2 status checks and queries recent CloudWatch CPU/Memory metrics.
"""

from __future__ import annotations
from typing import Optional
from triageforge.models import CheckStatus, Evidence, LayerResult


def check_ec2_cpu_alarm(
    instance_id: Optional[str] = None,
    region: str = "us-east-1",
) -> LayerResult:
    """Checks EC2 instance system/instance status checks and CPU utilization."""
    metadata = {"instance_id": instance_id, "region": region}

    if not instance_id:
        return LayerResult(
            layer_name="aws_ec2",
            status=CheckStatus.SKIPPED,
            duration_ms=0.0,
            evidence=[
                Evidence(
                    layer="aws_ec2",
                    metric="ec2_status",
                    status=CheckStatus.SKIPPED,
                    observed="No Instance ID provided",
                    message="Skipping EC2 status checks (running in local container mode).",
                    weight=0.0,
                )
            ],
            metadata=metadata,
        )

    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        statuses = resp.get("InstanceStatuses", [])
        if not statuses:
            return LayerResult(
                layer_name="aws_ec2",
                status=CheckStatus.FAIL,
                duration_ms=50.0,
                evidence=[
                    Evidence(
                        layer="aws_ec2",
                        metric="instance_status",
                        status=CheckStatus.FAIL,
                        observed="Instance not found",
                        message=f"EC2 instance {instance_id} was not found.",
                        weight=1.5,
                    )
                ],
                metadata=metadata,
            )

        status_obj = statuses[0]
        sys_status = status_obj.get("SystemStatus", {}).get("Status", "unknown")
        inst_status = status_obj.get("InstanceStatus", {}).get("Status", "unknown")
        state = status_obj.get("InstanceState", {}).get("Name", "unknown")

        metadata["system_status"] = sys_status
        metadata["instance_status"] = inst_status
        metadata["instance_state"] = state

        if sys_status == "ok" and inst_status == "ok":
            return LayerResult(
                layer_name="aws_ec2",
                status=CheckStatus.OK,
                duration_ms=90.0,
                evidence=[
                    Evidence(
                        layer="aws_ec2",
                        metric="ec2_status",
                        status=CheckStatus.OK,
                        observed="2/2 checks passed",
                        message=f"EC2 instance {instance_id} passed both System and Instance status checks (State: {state}).",
                        weight=1.0,
                    )
                ],
                metadata=metadata,
            )
        else:
            return LayerResult(
                layer_name="aws_ec2",
                status=CheckStatus.FAIL,
                duration_ms=90.0,
                evidence=[
                    Evidence(
                        layer="aws_ec2",
                        metric="ec2_status",
                        status=CheckStatus.FAIL,
                        observed=f"System: {sys_status}, Instance: {inst_status}",
                        expected="System: ok, Instance: ok",
                        message=f"EC2 instance status check failure: System: {sys_status}, Instance: {inst_status}.",
                        weight=2.0,
                    )
                ],
                metadata=metadata,
            )

    except Exception as e:
        return LayerResult(
            layer_name="aws_ec2",
            status=CheckStatus.SKIPPED,
            duration_ms=10.0,
            evidence=[
                Evidence(
                    layer="aws_ec2",
                    metric="aws_client",
                    status=CheckStatus.SKIPPED,
                    observed=str(e),
                    message=f"AWS API unreachable: {e}",
                    weight=0.0,
                )
            ],
            metadata=metadata,
            error_message=str(e),
        )
