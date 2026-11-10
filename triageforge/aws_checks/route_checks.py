"""
AWS Route Table Diagnostic Checks
Verifies that the subnet route table contains a default route to an Internet Gateway (igw-*).
"""

from __future__ import annotations
from typing import Optional
from triageforge.models import CheckStatus, Evidence, LayerResult


def check_route_table_igw(
    route_table_id: Optional[str] = None,
    region: str = "us-east-1",
) -> LayerResult:
    """Checks if route table contains 0.0.0.0/0 -> igw-* entry."""
    metadata = {"route_table_id": route_table_id, "region": region}

    if not route_table_id:
        return LayerResult(
            layer_name="aws_route",
            status=CheckStatus.SKIPPED,
            duration_ms=0.0,
            evidence=[
                Evidence(
                    layer="aws_route",
                    metric="route_igw",
                    status=CheckStatus.SKIPPED,
                    observed="No Route Table ID provided",
                    message="Skipping AWS route table check (running in local container mode).",
                    weight=0.0,
                )
            ],
            metadata=metadata,
        )

    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        resp = ec2.describe_route_tables(RouteTableIds=[route_table_id])
        tables = resp.get("RouteTables", [])
        if not tables:
            return LayerResult(
                layer_name="aws_route",
                status=CheckStatus.FAIL,
                duration_ms=50.0,
                evidence=[
                    Evidence(
                        layer="aws_route",
                        metric="route_exists",
                        status=CheckStatus.FAIL,
                        observed=f"Route table {route_table_id} not found",
                        message=f"Route table {route_table_id} does not exist in {region}.",
                        weight=1.5,
                    )
                ],
                metadata=metadata,
            )

        rt = tables[0]
        has_igw_default = False
        target_gw = ""

        for route in rt.get("Routes", []):
            if route.get("DestinationCidrBlock") == "0.0.0.0/0":
                gw_id = route.get("GatewayId", "")
                if gw_id.startswith("igw-"):
                    has_igw_default = True
                    target_gw = gw_id

        metadata["has_igw_default"] = has_igw_default
        metadata["gateway_id"] = target_gw

        if has_igw_default:
            return LayerResult(
                layer_name="aws_route",
                status=CheckStatus.OK,
                duration_ms=80.0,
                evidence=[
                    Evidence(
                        layer="aws_route",
                        metric="route_igw",
                        status=CheckStatus.OK,
                        observed=f"0.0.0.0/0 -> {target_gw}",
                        message=f"Route table {route_table_id} has valid default route to Internet Gateway ({target_gw}).",
                        weight=1.0,
                    )
                ],
                metadata=metadata,
            )
        else:
            return LayerResult(
                layer_name="aws_route",
                status=CheckStatus.FAIL,
                duration_ms=80.0,
                evidence=[
                    Evidence(
                        layer="aws_route",
                        metric="route_igw",
                        status=CheckStatus.FAIL,
                        observed="No 0.0.0.0/0 -> igw-* route found",
                        expected="0.0.0.0/0 target igw-xxxxxxxx",
                        message=f"Route table {route_table_id} lacks an Internet Gateway route. Instance cannot communicate with internet.",
                        weight=2.0,
                    )
                ],
                metadata=metadata,
                error_message="Missing default route to Internet Gateway.",
            )

    except Exception as e:
        return LayerResult(
            layer_name="aws_route",
            status=CheckStatus.SKIPPED,
            duration_ms=10.0,
            evidence=[
                Evidence(
                    layer="aws_route",
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
