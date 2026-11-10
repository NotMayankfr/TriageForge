"""
Unit tests for TriageForge individual diagnostic layers:
DNSLayer, TCPLayer, TLSLayer, HTTPLayer, and HostLayer.
"""

from pathlib import Path
import pytest
from triageforge.layers.dns_layer import DNSLayer
from triageforge.layers.host_layer import HostLayer
from triageforge.layers.http_layer import HTTPLayer
from triageforge.layers.tcp_layer import TCPLayer
from triageforge.layers.tls_layer import TLSLayer
from triageforge.models import CheckStatus


def test_dns_layer_ip_literal():
    layer = DNSLayer()
    res = layer.inspect("127.0.0.1")
    assert res.status == CheckStatus.OK
    assert res.metadata.get("is_ip_literal") is True


def test_dns_layer_localhost():
    layer = DNSLayer()
    res = layer.inspect("localhost")
    assert res.status == CheckStatus.OK
    assert "127.0.0.1" in res.metadata.get("resolved_ips", [])


def test_dns_layer_nxdomain():
    layer = DNSLayer()
    res = layer.inspect("this-domain-does-not-exist-at-all-xyz987.invalid")
    assert res.status == CheckStatus.FAIL
    assert len(res.evidence) > 0
    assert res.evidence[0].status == CheckStatus.FAIL


def test_tcp_layer_connection_refused():
    layer = TCPLayer(timeout_sec=1.0)
    # Port 59123 is typically not bound
    res = layer.inspect("127.0.0.1", port=59123)
    assert res.status == CheckStatus.FAIL
    assert res.metadata.get("state") in ("CONNECTION_REFUSED", "TIMEOUT", "ERROR_10061")


def test_tls_layer_skips_http():
    layer = TLSLayer()
    res = layer.inspect("http://localhost:80")
    assert res.status == CheckStatus.SKIPPED
    assert res.metadata.get("skipped") is True


def test_http_layer_signature_detection():
    layer = HTTPLayer()
    evidence = []
    sample_pg_body = "OperationalError: FATAL: too many clients already at /app/main.py"
    layer._detect_body_signatures(sample_pg_body, evidence)
    assert len(evidence) == 1
    assert evidence[0].metric == "signature_db_exhausted"

    sample_disk_body = "IOError: [Errno 28] No space left on device while writing /var/log/app.log"
    layer._detect_body_signatures(sample_disk_body, evidence)
    assert any(e.metric == "signature_disk_full" for e in evidence)

    sample_s3_body = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
    layer._detect_body_signatures(sample_s3_body, evidence)
    assert any(e.metric == "signature_iam_denied" for e in evidence)


def test_host_layer_disk_check():
    layer = HostLayer()
    evidence = []
    metadata = {}
    layer._check_disk_and_inodes(evidence, metadata)
    assert "disk_pct_used" in metadata
    assert "disk_free_gb" in metadata
    assert len(evidence) > 0
