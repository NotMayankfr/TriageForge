"""
TCP Diagnostic Layer
Inspects low-level TCP connectivity to the target port.
Crucially distinguishes between TIMEOUT (silent packet drop / firewall / blackhole)
and CONNECTION REFUSED (explicit TCP RST / service not listening).
"""

from __future__ import annotations
import errno
import socket
import time
from urllib.parse import urlparse

from triageforge.models import CheckStatus, Evidence, LayerResult


class TCPLayer:
    """Probes TCP port connectivity and analyzes socket-level failure states."""

    def __init__(self, timeout_sec: float = 4.0):
        self.timeout_sec = timeout_sec

    def inspect(self, url_or_host: str, port: int | None = None) -> LayerResult:
        start_time = time.perf_counter()
        evidence = []
        metadata = {}

        host, target_port = self._parse_target(url_or_host, port)
        metadata["host"] = host
        metadata["port"] = target_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_sec)

        try:
            connect_start = time.perf_counter()
            sock.connect((host, target_port))
            connect_duration_ms = (time.perf_counter() - connect_start) * 1000
            sock.close()

            metadata["tcp_handshake_ms"] = round(connect_duration_ms, 2)
            metadata["state"] = "CONNECTED"

            evidence.append(
                Evidence(
                    layer="tcp",
                    metric="tcp_connect",
                    status=CheckStatus.OK,
                    observed=f"Connected in {connect_duration_ms:.1f}ms",
                    expected="TCP SYN-ACK received",
                    message=f"TCP 3-way handshake established with {host}:{target_port} in {connect_duration_ms:.1f}ms.",
                    weight=1.0,
                )
            )

            if connect_duration_ms > 1500.0:
                evidence.append(
                    Evidence(
                        layer="tcp",
                        metric="tcp_latency",
                        status=CheckStatus.WARN,
                        observed=f"{connect_duration_ms:.1f}ms",
                        expected="< 500ms",
                        message=f"TCP connection establishment is sluggish ({connect_duration_ms:.1f}ms). Possible network throttling or buffer bloat.",
                        weight=0.7,
                    )
                )

            return LayerResult(
                layer_name="tcp",
                status=CheckStatus.OK,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                evidence=evidence,
                metadata=metadata,
            )

        except (socket.timeout, TimeoutError):
            connect_duration_ms = (time.perf_counter() - start_time) * 1000
            metadata["tcp_handshake_ms"] = round(connect_duration_ms, 2)
            metadata["state"] = "TIMEOUT"

            diag_msg = (
                f"TCP connection to {host}:{target_port} TIMED OUT after {self.timeout_sec}s. "
                "The SYN packet was transmitted but no SYN-ACK or RST was returned. "
                "This indicates silent packet dropping: a firewall (iptables/Security Group), "
                "a missing route, or an asymmetric routing blackhole."
            )

            evidence.append(
                Evidence(
                    layer="tcp",
                    metric="tcp_connect",
                    status=CheckStatus.FAIL,
                    observed="TIMEOUT (No response to SYN)",
                    expected=f"SYN-ACK within {self.timeout_sec}s",
                    message=diag_msg,
                    weight=2.0,
                )
            )

            return LayerResult(
                layer_name="tcp",
                status=CheckStatus.FAIL,
                duration_ms=round(connect_duration_ms, 2),
                evidence=evidence,
                metadata=metadata,
                error_message=diag_msg,
            )

        except OSError as e:
            connect_duration_ms = (time.perf_counter() - start_time) * 1000
            metadata["tcp_handshake_ms"] = round(connect_duration_ms, 2)
            err_no = e.errno

            # ECONNREFUSED check (errno 111 on Linux, 10061 on Windows)
            is_refused = err_no in (errno.ECONNREFUSED, 10061) or "refused" in str(e).lower()
            is_unreach = err_no in (getattr(errno, "EHOSTUNREACH", 113), getattr(errno, "ENETUNREACH", 101), 10065, 10051)

            if is_refused:
                metadata["state"] = "CONNECTION_REFUSED"
                diag_msg = (
                    f"Connection REFUSED by {host}:{target_port} (TCP RST received). "
                    "The destination host is online and network path is clear, but NO PROCESS is listening on this port, "
                    "or the target service (e.g. Nginx, Gunicorn) has stopped/crashed."
                )
                evidence.append(
                    Evidence(
                        layer="tcp",
                        metric="tcp_connect",
                        status=CheckStatus.FAIL,
                        observed="ECONNREFUSED (TCP RST received)",
                        expected=f"Process listening on port {target_port}",
                        message=diag_msg,
                        weight=2.0,
                    )
                )
            elif is_unreach:
                metadata["state"] = "HOST_UNREACHABLE"
                diag_msg = (
                    f"Host or network UNREACHABLE to {host}:{target_port} (ICMP Unreachable / no route). "
                    "Routing table lacks a default gateway or local interface is down."
                )
                evidence.append(
                    Evidence(
                        layer="tcp",
                        metric="tcp_connect",
                        status=CheckStatus.FAIL,
                        observed="EHOSTUNREACH",
                        expected="Active route to destination",
                        message=diag_msg,
                        weight=2.0,
                    )
                )
            else:
                metadata["state"] = f"ERROR_{err_no}"
                diag_msg = f"Socket error connecting to {host}:{target_port}: {e}"
                evidence.append(
                    Evidence(
                        layer="tcp",
                        metric="tcp_connect",
                        status=CheckStatus.FAIL,
                        observed=str(e),
                        expected="Clean connection",
                        message=diag_msg,
                        weight=1.5,
                    )
                )

            return LayerResult(
                layer_name="tcp",
                status=CheckStatus.FAIL,
                duration_ms=round(connect_duration_ms, 2),
                evidence=evidence,
                metadata=metadata,
                error_message=diag_msg,
            )
        finally:
            sock.close()

    def _parse_target(self, url_or_host: str, port: int | None) -> tuple[str, int]:
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            host = parsed.hostname or "127.0.0.1"
            if port is not None:
                target_port = port
            elif parsed.port:
                target_port = parsed.port
            elif parsed.scheme == "https":
                target_port = 443
            else:
                target_port = 80
        else:
            if ":" in url_or_host and not url_or_host.startswith("["):
                parts = url_or_host.split(":")
                host = parts[0]
                target_port = int(parts[1]) if port is None else port
            else:
                host = url_or_host
                target_port = port or 80
        return host, target_port
