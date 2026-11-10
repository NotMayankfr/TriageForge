"""
TLS Diagnostic Layer
Inspects TLS certificates, expiration dates, Subject Alternative Names (SANs),
hostname mismatches, and certificate chain errors.
"""

from __future__ import annotations
from datetime import datetime, timezone
import ssl
import socket
import time
from typing import List, Optional
from urllib.parse import urlparse

from triageforge.models import CheckStatus, Evidence, LayerResult


class TLSLayer:
    """Validates SSL/TLS certificates and handshake integrity."""

    def __init__(self, timeout_sec: float = 4.0):
        self.timeout_sec = timeout_sec

    def inspect(self, url_or_host: str, port: int | None = None) -> LayerResult:
        start_time = time.perf_counter()
        evidence: List[Evidence] = []
        metadata = {}

        host, target_port, is_https = self._parse_target(url_or_host, port)
        metadata["host"] = host
        metadata["port"] = target_port

        if not is_https and target_port not in (443, 8443):
            # Target is explicitly HTTP, skip TLS check
            return LayerResult(
                layer_name="tls",
                status=CheckStatus.SKIPPED,
                duration_ms=0.0,
                evidence=[
                    Evidence(
                        layer="tls",
                        metric="tls_skip",
                        status=CheckStatus.SKIPPED,
                        observed="HTTP protocol",
                        message=f"Target {url_or_host} is not using TLS (HTTP). TLS inspection skipped.",
                        weight=0.0,
                    )
                ],
                metadata={"skipped": True, "reason": "Target uses plain HTTP"},
            )

        # First attempt: standard strict validation with default system CA store
        context_strict = ssl.create_default_context()
        cert_data = None
        handshake_error = None
        is_cert_untrusted = False

        try:
            with socket.create_connection((host, target_port), timeout=self.timeout_sec) as sock:
                with context_strict.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_data = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    metadata["cipher"] = cipher[0] if cipher else "Unknown"
                    metadata["protocol"] = version

        except ssl.SSLCertVerificationError as e:
            is_cert_untrusted = True
            handshake_error = e
        except ssl.SSLError as e:
            handshake_error = e
        except Exception as e:
            # Network level failure handled in TCP layer
            return LayerResult(
                layer_name="tls",
                status=CheckStatus.FAIL,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
                evidence=[
                    Evidence(
                        layer="tls",
                        metric="tls_handshake",
                        status=CheckStatus.FAIL,
                        observed=str(e),
                        message=f"Cannot establish TLS connection to {host}:{target_port}: {e}",
                        weight=1.5,
                    )
                ],
                metadata=metadata,
                error_message=str(e),
            )

        # If strict verification failed, query peer cert without verification to analyze the cert details
        if cert_data is None:
            try:
                context_relaxed = ssl.create_default_context()
                context_relaxed.check_hostname = False
                context_relaxed.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, target_port), timeout=self.timeout_sec) as sock:
                    with context_relaxed.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_data = ssock.getpeercert()
                        metadata["cipher"] = ssock.cipher()[0] if ssock.cipher() else "Unknown"
                        metadata["protocol"] = ssock.version()
            except Exception:
                pass

        now = datetime.now(timezone.utc)

        # If we got cert data (either strict or relaxed), analyze expiration and SAN
        if cert_data:
            not_after_str = cert_data.get("notAfter")
            not_before_str = cert_data.get("notBefore")
            subject = dict(x[0] for x in cert_data.get("subject", []))
            issuer = dict(x[0] for x in cert_data.get("issuer", []))
            san_entries = [v for k, v in cert_data.get("subjectAltName", []) if k == "DNS" or k == "IP Address"]

            metadata["common_name"] = subject.get("commonName", "Unknown")
            metadata["issuer_cn"] = issuer.get("commonName", "Unknown")
            metadata["sans"] = san_entries

            # Check expiration
            if not_after_str:
                # Format: 'Mar 10 12:00:00 2024 GMT'
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    metadata["expires_at"] = not_after.isoformat()
                    days_remaining = (not_after - now).total_seconds() / 86400.0
                    metadata["days_remaining"] = round(days_remaining, 1)

                    if days_remaining < 0:
                        evidence.append(
                            Evidence(
                                layer="tls",
                                metric="cert_expiry",
                                status=CheckStatus.FAIL,
                                observed=f"Expired {abs(days_remaining):.1f} days ago ({not_after_str})",
                                expected=f"Valid after {now.strftime('%b %d %Y')}",
                                message=f"TLS certificate for {host} EXPIRED on {not_after_str} ({abs(days_remaining):.1f} days ago).",
                                weight=2.0,
                            )
                        )
                    elif days_remaining < 14:
                        evidence.append(
                            Evidence(
                                layer="tls",
                                metric="cert_expiry",
                                status=CheckStatus.WARN,
                                observed=f"Expires in {days_remaining:.1f} days ({not_after_str})",
                                expected="> 30 days remaining",
                                message=f"TLS certificate is nearing expiration ({days_remaining:.1f} days remaining).",
                                weight=1.0,
                            )
                        )
                    else:
                        evidence.append(
                            Evidence(
                                layer="tls",
                                metric="cert_expiry",
                                status=CheckStatus.OK,
                                observed=f"Valid for {days_remaining:.1f} days",
                                message=f"Certificate is valid until {not_after_str} ({days_remaining:.1f} days remaining).",
                                weight=0.5,
                            )
                        )
                except Exception:
                    pass

            # Check SAN / Hostname match
            cn = subject.get("commonName", "")
            host_matches = (host == cn) or any(self._match_san(host, san) for san in san_entries)
            metadata["hostname_matches_cert"] = host_matches

            if not host_matches and host not in ("127.0.0.1", "localhost"):
                evidence.append(
                    Evidence(
                        layer="tls",
                        metric="cert_hostname_mismatch",
                        status=CheckStatus.FAIL,
                        observed=f"CN='{cn}', SANs={san_entries}",
                        expected=f"Matching '{host}'",
                        message=f"TLS certificate hostname mismatch: Requested host '{host}' is NOT present in certificate SANs ({', '.join(san_entries) or cn}).",
                        weight=2.0,
                    )
                )

        # Handle verification errors
        if is_cert_untrusted:
            err_reason = str(handshake_error)
            evidence.append(
                Evidence(
                    layer="tls",
                    metric="cert_trust_chain",
                    status=CheckStatus.FAIL,
                    observed="SSLCertVerificationError",
                    expected="Valid CA chain or trusted self-signed cert",
                    message=f"TLS certificate verification failed: {err_reason}. Untrusted CA, expired cert, or self-signed cert.",
                    weight=1.8,
                )
            )

        # Determine overall layer status
        has_fail = any(e.status == CheckStatus.FAIL for e in evidence)
        has_warn = any(e.status == CheckStatus.WARN for e in evidence)
        status = CheckStatus.FAIL if has_fail else (CheckStatus.WARN if has_warn else CheckStatus.OK)

        if status == CheckStatus.OK and not evidence:
            evidence.append(
                Evidence(
                    layer="tls",
                    metric="tls_valid",
                    status=CheckStatus.OK,
                    observed="Valid",
                    message=f"TLS handshake and certificate valid for {host}:{target_port}.",
                    weight=1.0,
                )
            )

        duration_ms = (time.perf_counter() - start_time) * 1000
        return LayerResult(
            layer_name="tls",
            status=status,
            duration_ms=round(duration_ms, 2),
            evidence=evidence,
            metadata=metadata,
            error_message=str(handshake_error) if handshake_error else None,
        )

    def _match_san(self, host: str, san: str) -> bool:
        if san.startswith("*."):
            domain_suffix = san[2:]
            return host.endswith(domain_suffix) and host.count(".") == san.count(".")
        return host.lower() == san.lower()

    def _parse_target(self, url_or_host: str, port: int | None) -> tuple[str, int, bool]:
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            host = parsed.hostname or "127.0.0.1"
            is_https = parsed.scheme.lower() == "https"
            if port is not None:
                target_port = port
            elif parsed.port:
                target_port = parsed.port
            else:
                target_port = 443 if is_https else 80
        else:
            host = url_or_host.split(":")[0]
            target_port = port or 443
            is_https = target_port == 443
        return host, target_port, is_https
