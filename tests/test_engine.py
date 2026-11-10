"""
Unit Tests for TriageForge Deterministic Diagnosis Engine
Asserts deterministic hypothesis ranking, confidence scoring, and root-cause classification.
"""

import pytest
from triageforge.engine import DiagnosisEngine
from triageforge.models import CheckStatus, Evidence, LayerResult


@pytest.fixture
def engine():
    return DiagnosisEngine()


def test_healthy_stack(engine):
    """Verifies that an all-pass telemetry profile results in a healthy report."""
    layers = {
        "dns": LayerResult(
            layer_name="dns",
            status=CheckStatus.OK,
            duration_ms=1.2,
            evidence=[Evidence(layer="dns", metric="dns_resolution", status=CheckStatus.OK, observed=["127.0.0.1"], message="Resolved OK")],
        ),
        "tcp": LayerResult(
            layer_name="tcp",
            status=CheckStatus.OK,
            duration_ms=2.0,
            metadata={"state": "CONNECTED", "host": "127.0.0.1", "port": 80},
            evidence=[Evidence(layer="tcp", metric="tcp_connect", status=CheckStatus.OK, observed="Connected in 2ms", message="Handshake OK")],
        ),
        "http": LayerResult(
            layer_name="http",
            status=CheckStatus.OK,
            duration_ms=12.5,
            metadata={"status_code": 200, "server": "nginx"},
            evidence=[Evidence(layer="http", metric="http_status", status=CheckStatus.OK, observed="HTTP 200 OK", message="Endpoint OK")],
        ),
    }

    report = engine.analyze(target_url="http://localhost:80", layers=layers)
    assert report.is_healthy is True
    assert report.top_hypothesis is None
    assert len(report.hypotheses) == 0


def test_diagnose_sg_block_timeout(engine):
    """Verifies that DNS PASS + TCP TIMEOUT results in 01_sg_block diagnosis."""
    layers = {
        "dns": LayerResult(
            layer_name="dns",
            status=CheckStatus.OK,
            duration_ms=1.5,
            evidence=[Evidence(layer="dns", metric="dns_resolution", status=CheckStatus.OK, observed=["127.0.0.1"], message="Resolved OK")],
        ),
        "tcp": LayerResult(
            layer_name="tcp",
            status=CheckStatus.FAIL,
            duration_ms=4000.0,
            metadata={"state": "TIMEOUT", "host": "127.0.0.1", "port": 443},
            evidence=[
                Evidence(
                    layer="tcp",
                    metric="tcp_connect",
                    status=CheckStatus.FAIL,
                    observed="TIMEOUT (No response to SYN)",
                    message="Silent packet drop",
                    weight=2.0,
                )
            ],
        ),
    }

    report = engine.analyze(target_url="https://localhost:443", layers=layers)
    assert report.is_healthy is False
    assert report.top_hypothesis is not None
    assert report.top_hypothesis.fault_type == "01_sg_block"
    assert report.top_hypothesis.confidence >= 0.90
    assert "Firewall / Security Group" in report.top_hypothesis.title


def test_diagnose_gunicorn_down_502(engine):
    """Verifies that Nginx 502 Bad Gateway results in 02_gunicorn_down diagnosis."""
    layers = {
        "dns": LayerResult(
            layer_name="dns",
            status=CheckStatus.OK,
            duration_ms=0.5,
            evidence=[],
        ),
        "tcp": LayerResult(
            layer_name="tcp",
            status=CheckStatus.OK,
            duration_ms=1.0,
            metadata={"state": "CONNECTED"},
            evidence=[],
        ),
        "http": LayerResult(
            layer_name="http",
            status=CheckStatus.FAIL,
            duration_ms=25.0,
            metadata={"status_code": 502, "server": "nginx/1.25.4"},
            evidence=[
                Evidence(
                    layer="http",
                    metric="http_status",
                    status=CheckStatus.FAIL,
                    observed="HTTP 502 Bad Gateway",
                    message="Reverse proxy cannot connect to upstream",
                    weight=2.0,
                )
            ],
        ),
    }

    report = engine.analyze(target_url="http://localhost:80", layers=layers)
    assert report.is_healthy is False
    assert report.top_hypothesis is not None
    assert report.top_hypothesis.fault_type == "02_gunicorn_down"
    assert report.top_hypothesis.confidence >= 0.90


def test_diagnose_pg_connection_exhaustion(engine):
    """Verifies that PostgreSQL connection saturation signature is identified."""
    layers = {
        "http": LayerResult(
            layer_name="http",
            status=CheckStatus.FAIL,
            duration_ms=10.0,
            metadata={"status_code": 500},
            evidence=[
                Evidence(
                    layer="http",
                    metric="signature_db_exhausted",
                    status=CheckStatus.FAIL,
                    observed="FATAL: too many clients already",
                    message="Connection pool exhausted",
                    weight=2.0,
                )
            ],
        ),
        "host": LayerResult(
            layer_name="host",
            status=CheckStatus.FAIL,
            duration_ms=50.0,
            metadata={"pg_active_connections": 20, "pg_max_connections": 20},
            evidence=[
                Evidence(
                    layer="host",
                    metric="pg_connection_exhaustion",
                    status=CheckStatus.FAIL,
                    observed="20/20 used",
                    message="PostgreSQL saturated",
                    weight=2.0,
                )
            ],
        ),
    }

    report = engine.analyze(target_url="http://localhost:80/api/items", layers=layers)
    assert report.top_hypothesis is not None
    assert report.top_hypothesis.fault_type == "04_pg_connections"
    assert report.top_hypothesis.confidence >= 0.95


def test_diagnose_disk_full(engine):
    """Verifies that disk and inode exhaustion is correctly identified."""
    layers = {
        "host": LayerResult(
            layer_name="host",
            status=CheckStatus.FAIL,
            duration_ms=5.0,
            metadata={"disk_pct_used": 99.2, "disk_free_gb": 0.05},
            evidence=[
                Evidence(
                    layer="host",
                    metric="disk_space",
                    status=CheckStatus.FAIL,
                    observed="99.2% used",
                    message="CRITICAL DISK SPACE EXHAUSTION",
                    weight=2.0,
                )
            ],
        )
    }

    report = engine.analyze(target_url="http://localhost:80", layers=layers)
    assert report.top_hypothesis is not None
    assert report.top_hypothesis.fault_type == "03_disk_full"
    assert report.top_hypothesis.confidence >= 0.95


def test_diagnose_expired_tls(engine):
    """Verifies that expired TLS certificates are flagged with high confidence."""
    layers = {
        "tls": LayerResult(
            layer_name="tls",
            status=CheckStatus.FAIL,
            duration_ms=15.0,
            metadata={"days_remaining": -30.0},
            evidence=[
                Evidence(
                    layer="tls",
                    metric="cert_expiry",
                    status=CheckStatus.FAIL,
                    observed="Expired 30 days ago",
                    message="TLS certificate expired",
                    weight=2.0,
                )
            ],
        )
    }

    report = engine.analyze(target_url="https://localhost:443", layers=layers)
    assert report.top_hypothesis is not None
    assert report.top_hypothesis.fault_type == "07_expired_tls"
    assert report.top_hypothesis.confidence >= 0.90


def test_diagnose_oom_killer(engine):
    """Verifies that kernel OOM events and exit 137 are diagnosed."""
    layers = {
        "host": LayerResult(
            layer_name="host",
            status=CheckStatus.FAIL,
            duration_ms=10.0,
            evidence=[
                Evidence(
                    layer="host",
                    metric="container_oom_kill",
                    status=CheckStatus.FAIL,
                    observed="triageforge-app OOMKilled=True, ExitCode=137",
                    message="CONTAINER OOM KILL DETECTED",
                    weight=2.0,
                )
            ],
        )
    }

    report = engine.analyze(target_url="http://localhost:80", layers=layers)
    assert report.top_hypothesis is not None
    assert report.top_hypothesis.fault_type == "09_oom_killed"
    assert report.top_hypothesis.confidence >= 0.95
