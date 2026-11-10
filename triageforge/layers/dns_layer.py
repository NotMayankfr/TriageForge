"""
DNS Diagnostic Layer
Diagnoses name resolution failures, separating NXDOMAIN, SERVFAIL, timeouts, and local resolver corruption.
"""

from __future__ import annotations
import socket
import time
from typing import List, Tuple
from urllib.parse import urlparse

from triageforge.models import CheckStatus, Evidence, LayerResult


class DNSLayer:
    """Inspects DNS resolution for a target hostname."""

    def __init__(self, timeout_sec: float = 3.0):
        self.timeout_sec = timeout_sec

    def inspect(self, url_or_host: str) -> LayerResult:
        start_time = time.perf_counter()
        evidence: List[Evidence] = []
        metadata = {}

        hostname = self._extract_host(url_or_host)
        metadata["hostname"] = hostname

        # IP literal fast-path (e.g., 127.0.0.1 or 192.168.1.1)
        if self._is_ip_address(hostname):
            duration_ms = (time.perf_counter() - start_time) * 1000
            evidence.append(
                Evidence(
                    layer="dns",
                    metric="ip_literal",
                    status=CheckStatus.OK,
                    observed=hostname,
                    message=f"Target '{hostname}' is an IP literal. DNS resolution bypassed.",
                    weight=0.5,
                )
            )
            return LayerResult(
                layer_name="dns",
                status=CheckStatus.OK,
                duration_ms=round(duration_ms, 2),
                evidence=evidence,
                metadata={"resolved_ips": [hostname], "is_ip_literal": True},
            )

        # Attempt DNS resolution
        resolved_ips: List[str] = []
        try:
            dns_start = time.perf_counter()
            # Query IPv4 and IPv6 addresses
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            dns_duration_ms = (time.perf_counter() - dns_start) * 1000

            for entry in addr_info:
                sockaddr = entry[4]
                ip = sockaddr[0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)

            metadata["resolved_ips"] = resolved_ips
            metadata["dns_latency_ms"] = round(dns_duration_ms, 2)

            if dns_duration_ms > 1000.0:
                evidence.append(
                    Evidence(
                        layer="dns",
                        metric="dns_latency",
                        status=CheckStatus.WARN,
                        observed=f"{dns_duration_ms:.1f}ms",
                        expected="< 200ms",
                        message=f"High DNS resolution latency ({dns_duration_ms:.1f}ms) detected.",
                        weight=0.8,
                    )
                )

            evidence.append(
                Evidence(
                    layer="dns",
                    metric="dns_resolution",
                    status=CheckStatus.OK,
                    observed=resolved_ips,
                    message=f"Successfully resolved '{hostname}' to {len(resolved_ips)} IP(s): {', '.join(resolved_ips)}.",
                    weight=1.0,
                )
            )
            status = CheckStatus.OK
            error_msg = None

        except socket.gaierror as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            err_code = e.errno
            err_str = str(e)
            metadata["error_code"] = err_code
            metadata["error_str"] = err_str

            # Classify DNS failure
            # Typically 11001 (Windows) or -2 (EAI_NONAME on Linux)
            is_nxdomain = err_code in (socket.EAI_NONAME, 11001) if hasattr(socket, "EAI_NONAME") else "Name or service not known" in err_str
            # EAI_AGAIN (-3 or 11002 on Windows) means timeout / nameserver failure
            is_timeout = err_code in (getattr(socket, "EAI_AGAIN", -3), 11002) or "Temporary failure" in err_str

            if is_nxdomain:
                diag_msg = f"NXDOMAIN / Name not known: Hostname '{hostname}' has no DNS records or domain does not exist."
            elif is_timeout:
                diag_msg = f"DNS Timeout / SERVFAIL: Nameserver unreachable or timed out querying '{hostname}'."
            else:
                diag_msg = f"DNS resolution failed for '{hostname}': {err_str} (code {err_code})."

            evidence.append(
                Evidence(
                    layer="dns",
                    metric="dns_resolution",
                    status=CheckStatus.FAIL,
                    observed=f"Error {err_code}: {err_str}",
                    expected="Valid A/AAAA record",
                    message=diag_msg,
                    weight=1.5,
                )
            )
            status = CheckStatus.FAIL
            error_msg = diag_msg

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            evidence.append(
                Evidence(
                    layer="dns",
                    metric="dns_resolution",
                    status=CheckStatus.FAIL,
                    observed=str(e),
                    expected="Valid A/AAAA record",
                    message=f"Unexpected error during DNS resolution: {e}",
                    weight=1.5,
                )
            )
            status = CheckStatus.FAIL
            error_msg = str(e)

        total_duration_ms = (time.perf_counter() - start_time) * 1000
        return LayerResult(
            layer_name="dns",
            status=status,
            duration_ms=round(total_duration_ms, 2),
            evidence=evidence,
            metadata=metadata,
            error_message=error_msg,
        )

    def _extract_host(self, url_or_host: str) -> str:
        if "://" not in url_or_host:
            url_or_host = f"http://{url_or_host}"
        parsed = urlparse(url_or_host)
        return parsed.hostname or url_or_host

    def _is_ip_address(self, host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except (socket.error, OSError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except (socket.error, OSError):
            return False
