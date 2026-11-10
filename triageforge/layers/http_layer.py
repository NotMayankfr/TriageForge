"""
HTTP Diagnostic Layer
Inspects HTTP/HTTPS response codes, latency breakdown (DNS, TCP, TLS, TTFB),
response headers, and error body signatures.
"""

from __future__ import annotations
import http.client
import socket
import ssl
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from triageforge.models import CheckStatus, Evidence, LayerResult


class HTTPLayer:
    """Performs HTTP diagnostic requests with precise timing breakdown and signature detection."""

    def __init__(self, timeout_sec: float = 6.0):
        self.timeout_sec = timeout_sec

    def inspect(self, url: str) -> LayerResult:
        start_total = time.perf_counter()
        evidence: List[Evidence] = []
        metadata: Dict[str, any] = {}

        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        parsed = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        metadata["url"] = url
        metadata["host"] = host
        metadata["port"] = port
        metadata["path"] = path

        # Timing breakdown measurements
        dns_start = time.perf_counter()
        try:
            ip = socket.gethostbyname(host)
            dns_time_ms = (time.perf_counter() - dns_start) * 1000
            metadata["resolved_ip"] = ip
            metadata["dns_time_ms"] = round(dns_time_ms, 2)
        except Exception:
            dns_time_ms = 0.0

        # Create connection based on scheme
        tcp_start = time.perf_counter()
        try:
            if is_https:
                ctx = ssl.create_default_context()
                # For triage diagnostics, allow insecure fallback to inspect HTTP status even if cert is self-signed/expired
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout_sec, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout_sec)

            conn.connect()
            tcp_time_ms = (time.perf_counter() - tcp_start) * 1000
            metadata["tcp_time_ms"] = round(tcp_time_ms, 2)

            # Send HTTP Request
            req_start = time.perf_counter()
            conn.putrequest("GET", path)
            conn.putheader("Host", host)
            conn.putheader("User-Agent", "TriageForge-Diagnostic-Probe/1.0")
            conn.putheader("Accept", "*/*")
            conn.endheaders()

            # Measure TTFB (Time to First Byte)
            resp = conn.getresponse()
            ttfb_ms = (time.perf_counter() - req_start) * 1000
            metadata["ttfb_ms"] = round(ttfb_ms, 2)

            # Read response body
            body_bytes = resp.read(8192)  # Read first 8KB
            body_str = body_bytes.decode("utf-8", errors="replace")
            conn.close()

            status_code = resp.status
            reason = resp.reason
            headers = dict(resp.getheaders())
            server_header = headers.get("server", headers.get("Server", "Unknown"))

            metadata["status_code"] = status_code
            metadata["reason"] = reason
            metadata["server"] = server_header
            metadata["content_type"] = headers.get("content-type", "")

            # Analyze HTTP Status
            if status_code == 200:
                evidence.append(
                    Evidence(
                        layer="http",
                        metric="http_status",
                        status=CheckStatus.OK,
                        observed=f"HTTP 200 {reason}",
                        message=f"Endpoint returned HTTP 200 OK (TTFB: {ttfb_ms:.1f}ms).",
                        weight=1.0,
                    )
                )
            elif status_code == 502:
                evidence.append(
                    Evidence(
                        layer="http",
                        metric="http_status",
                        status=CheckStatus.FAIL,
                        observed=f"HTTP 502 Bad Gateway (Server: {server_header})",
                        expected="HTTP 200 OK",
                        message=(
                            f"HTTP 502 Bad Gateway returned by {server_header}. "
                            "The reverse proxy (Nginx) cannot connect to or receive a response from the upstream application (Gunicorn/FastAPI)."
                        ),
                        weight=2.0,
                    )
                )
            elif status_code == 504:
                evidence.append(
                    Evidence(
                        layer="http",
                        metric="http_status",
                        status=CheckStatus.FAIL,
                        observed=f"HTTP 504 Gateway Timeout (Server: {server_header})",
                        expected="HTTP 200 OK",
                        message=(
                            f"HTTP 504 Gateway Timeout returned by {server_header}. "
                            "Upstream application accepted connection but did not complete response within proxy timeout."
                        ),
                        weight=2.0,
                    )
                )
            elif status_code == 500:
                evidence.append(
                    Evidence(
                        layer="http",
                        metric="http_status",
                        status=CheckStatus.FAIL,
                        observed=f"HTTP 500 Internal Server Error",
                        expected="HTTP 200 OK",
                        message=f"HTTP 500 Internal Server Error returned by application. Check application logs for unhandled exceptions.",
                        weight=1.8,
                    )
                )
            elif status_code == 403:
                evidence.append(
                    Evidence(
                        layer="http",
                        metric="http_status",
                        status=CheckStatus.FAIL,
                        observed=f"HTTP 403 Forbidden",
                        expected="HTTP 200 OK",
                        message="HTTP 403 Forbidden: Request was rejected due to permission/authorization denial.",
                        weight=1.5,
                    )
                )
            else:
                evidence.append(
                    Evidence(
                        layer="http",
                        metric="http_status",
                        status=CheckStatus.WARN if status_code >= 400 else CheckStatus.OK,
                        observed=f"HTTP {status_code} {reason}",
                        message=f"Received HTTP {status_code} {reason}.",
                        weight=1.0,
                    )
                )

            # Analyze Response Body Signatures
            self._detect_body_signatures(body_str, evidence)

            total_duration_ms = (time.perf_counter() - start_total) * 1000
            has_fail = any(e.status == CheckStatus.FAIL for e in evidence)
            has_warn = any(e.status == CheckStatus.WARN for e in evidence)
            layer_status = CheckStatus.FAIL if has_fail else (CheckStatus.WARN if has_warn else CheckStatus.OK)

            return LayerResult(
                layer_name="http",
                status=layer_status,
                duration_ms=round(total_duration_ms, 2),
                evidence=evidence,
                metadata=metadata,
            )

        except Exception as e:
            total_duration_ms = (time.perf_counter() - start_total) * 1000
            err_msg = str(e)
            evidence.append(
                Evidence(
                    layer="http",
                    metric="http_request",
                    status=CheckStatus.FAIL,
                    observed=err_msg,
                    expected="HTTP Response",
                    message=f"Failed to complete HTTP transaction: {err_msg}",
                    weight=1.5,
                )
            )
            return LayerResult(
                layer_name="http",
                status=CheckStatus.FAIL,
                duration_ms=round(total_duration_ms, 2),
                evidence=evidence,
                metadata=metadata,
                error_message=err_msg,
            )

    def _detect_body_signatures(self, body: str, evidence: List[Evidence]) -> None:
        """Inspects response content for specific signatures."""
        lower_body = body.lower()

        # Database connection exhaustion signature
        if "too many clients" in lower_body or "remaining connection slots" in lower_body or "operationalerror: fatal" in lower_body:
            evidence.append(
                Evidence(
                    layer="http",
                    metric="signature_db_exhausted",
                    status=CheckStatus.FAIL,
                    observed="Database connection pool exhaustion signature in response body",
                    expected="Normal response payload",
                    message="Response body contains PostgreSQL connection exhaustion message ('too many clients already').",
                    weight=2.0,
                )
            )

        # Disk full signature
        if "no space left on device" in lower_body or "enospc" in lower_body:
            evidence.append(
                Evidence(
                    layer="http",
                    metric="signature_disk_full",
                    status=CheckStatus.FAIL,
                    observed="Disk full signature ('No space left on device') in body",
                    expected="Normal response payload",
                    message="Application encountered ENOSPC / 'No space left on device' while writing logs or temp files.",
                    weight=2.0,
                )
            )

        # IAM / S3 AccessDenied XML signature
        if "<code >accessdenied</code >" in lower_body or "<code >accessdenied" in lower_body or "<code >unauthorizedoperation" in lower_body or "accessdenied" in lower_body:
            evidence.append(
                Evidence(
                    layer="http",
                    metric="signature_iam_denied",
                    status=CheckStatus.FAIL,
                    observed="AccessDenied error payload in response body",
                    expected="Normal storage response",
                    message="Detected AWS/S3 AccessDenied signature in response: IAM role lacks requisite S3 permissions.",
                    weight=2.0,
                )
            )
