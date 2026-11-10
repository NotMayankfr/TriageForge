"""
TriageForge Log & VPC Flow Analyzer
Analyzes AWS VPC Flow Logs for rejected packet flows and parses web server access logs
for error distribution and latency spikes.
"""

from __future__ import annotations
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional


class LogAnalyzer:
    """Parses and analyzes VPC Flow Logs and Nginx logs for incident diagnostics."""

    def analyze_vpc_flow_logs(self, log_content_or_path: str | Path) -> Dict[str, Any]:
        """Parses standard AWS VPC Flow Log format and highlights dropped/rejected traffic."""
        lines = self._get_lines(log_content_or_path)

        total_records = 0
        accepted_count = 0
        rejected_count = 0
        rejected_ports = Counter()
        rejected_sources = Counter()

        for line in lines:
            parts = line.strip().split()
            if len(parts) < 14:
                continue
            # Header line: version account-id interface-id ...
            if parts[0] == "version" or not parts[0].isdigit():
                continue

            total_records += 1
            src_addr = parts[3]
            dst_port = parts[6]
            protocol = parts[7]
            action = parts[12].upper()

            if action == "REJECT":
                rejected_count += 1
                rejected_ports[dst_port] += 1
                rejected_sources[src_addr] += 1
            elif action == "ACCEPT":
                accepted_count += 1

        reject_rate = (rejected_count / max(1, total_records)) * 100.0

        findings = []
        if rejected_count > 0:
            top_ports = [f"port {p} ({c}x)" for p, c in rejected_ports.most_common(3)]
            findings.append(
                f"VPC Security Group / NACL dropped {rejected_count} flow(s) ({reject_rate:.1f}% reject rate). "
                f"Top blocked ports: {', '.join(top_ports)}."
            )
        else:
            findings.append("Zero rejected traffic flows detected in VPC Flow Logs.")

        return {
            "total_flows": total_records,
            "accepted_flows": accepted_count,
            "rejected_flows": rejected_count,
            "reject_rate_pct": round(reject_rate, 2),
            "top_rejected_ports": dict(rejected_ports.most_common(5)),
            "top_rejected_sources": dict(rejected_sources.most_common(5)),
            "findings": findings,
        }

    def analyze_nginx_logs(self, log_content_or_path: str | Path) -> Dict[str, Any]:
        """Parses Nginx access logs and computes error rates and status code breakdowns."""
        lines = self._get_lines(log_content_or_path)

        total_requests = 0
        status_counts = Counter()
        failing_endpoints = Counter()

        # Regex for standard or extended Nginx combined access log
        # e.g.: 172.18.0.1 - - [10/Nov/2024:14:22:45 +0000] "GET /api/items HTTP/1.1" 502 157 ...
        pattern = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[A-Z0-9/.]+"\s+(?P<status>\d{3})')

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            match = pattern.search(line_str)
            if match:
                total_requests += 1
                status = int(match.group("status"))
                uri = match.group("uri")
                status_counts[status] += 1

                if status >= 500:
                    failing_endpoints[uri] += 1

        c5xx = sum(count for status, count in status_counts.items() if status >= 500)
        c4xx = sum(count for status, count in status_counts.items() if 400 <= status < 500)
        c2xx = sum(count for status, count in status_counts.items() if 200 <= status < 300)

        error_rate_5xx = (c5xx / max(1, total_requests)) * 100.0

        findings = []
        if c5xx > 0:
            top_endpoints = [f"'{u}' ({c} errors)" for u, c in failing_endpoints.most_common(3)]
            findings.append(
                f"Elevated 5xx server error rate detected: {c5xx} failure(s) ({error_rate_5xx:.1f}% error rate). "
                f"Top failing URIs: {', '.join(top_endpoints)}."
            )
        else:
            findings.append("HTTP access logs reflect healthy nominal response distribution (0% 5xx errors).")

        return {
            "total_requests": total_requests,
            "status_breakdown": dict(status_counts),
            "2xx_success": c2xx,
            "4xx_client_errors": c4xx,
            "5xx_server_errors": c5xx,
            "error_rate_5xx_pct": round(error_rate_5xx, 2),
            "failing_endpoints": dict(failing_endpoints.most_common(5)),
            "findings": findings,
        }

    def _get_lines(self, log_content_or_path: str | Path) -> List[str]:
        if isinstance(log_content_or_path, Path) or (isinstance(log_content_or_path, str) and "\n" not in log_content_or_path and Path(log_content_or_path).exists()):
            return Path(log_content_or_path).read_text(encoding="utf-8", errors="replace").splitlines()
        return str(log_content_or_path).splitlines()
