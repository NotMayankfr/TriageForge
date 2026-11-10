"""
TriageForge Deterministic Diagnosis Engine
Analyzes multi-layer telemetry and evidence, applying deterministic rule-based
hypotheses ranking with confidence scoring and actionable SRE runbook commands.
"""

from __future__ import annotations
from typing import Dict, List, Optional

from triageforge.models import (
    CheckStatus,
    DiagnosticReport,
    Evidence,
    Hypothesis,
    LayerResult,
)


class DiagnosisEngine:
    """Deterministic, rule-based inference engine for cloud and local stack triage."""

    def analyze(
        self,
        target_url: str,
        layers: Dict[str, LayerResult],
        execution_time_ms: float = 0.0,
    ) -> DiagnosticReport:
        all_evidence: List[Evidence] = []
        for l in layers.values():
            all_evidence.extend(l.evidence)

        # Generate candidate hypotheses by matching rule patterns against observed evidence
        candidates: List[Hypothesis] = []

        # 1. Rule: DNS Failure (Fault 06)
        cand_dns = self._evaluate_bad_dns(layers)
        if cand_dns:
            candidates.append(cand_dns)

        # 2. Rule: TCP Timeout / Firewall Block / Security Group (Fault 01)
        cand_sg = self._evaluate_sg_block(layers)
        if cand_sg:
            candidates.append(cand_sg)

        # 2b. Rule: TCP Connection Refused on Port 80/443 (Ingress Proxy Down)
        cand_ingress = self._evaluate_ingress_down(layers)
        if cand_ingress:
            candidates.append(cand_ingress)

        # 3. Rule: Connection Refused / Gunicorn Down / Nginx 502 (Fault 02)
        cand_gunicorn = self._evaluate_gunicorn_down(layers)
        if cand_gunicorn:
            candidates.append(cand_gunicorn)

        # 4. Rule: Disk / Inode Full (Fault 03)
        cand_disk = self._evaluate_disk_full(layers)
        if cand_disk:
            candidates.append(cand_disk)

        # 5. Rule: PostgreSQL Connection Saturation (Fault 04)
        cand_pg = self._evaluate_pg_connections(layers)
        if cand_pg:
            candidates.append(cand_pg)

        # 6. Rule: Missing Route / Gateway Egress Blackhole (Fault 05)
        cand_route = self._evaluate_missing_route(layers)
        if cand_route:
            candidates.append(cand_route)

        # 7. Rule: Expired or Mismatched TLS Certificate (Fault 07)
        cand_tls = self._evaluate_tls_failure(layers)
        if cand_tls:
            candidates.append(cand_tls)

        # 8. Rule: IAM / Storage S3 AccessDenied (Fault 08)
        cand_iam = self._evaluate_iam_s3_denied(layers)
        if cand_iam:
            candidates.append(cand_iam)

        # 9. Rule: OOM Killer / Memory Leak (Fault 09)
        cand_oom = self._evaluate_oom_killer(layers)
        if cand_oom:
            candidates.append(cand_oom)

        # 10. Rule: SSH Lockout / Bad Permissions (Fault 10)
        cand_ssh = self._evaluate_ssh_lockout(layers)
        if cand_ssh:
            candidates.append(cand_ssh)

        # Sort hypotheses by confidence descending
        candidates.sort(key=lambda h: h.confidence, reverse=True)

        is_healthy = len(candidates) == 0
        top_hypo = candidates[0] if candidates else None

        if is_healthy:
            summary = "All diagnostic layers passed nominal thresholds. Stack is healthy and responsive."
        else:
            summary = (
                f"Triage identified {len(candidates)} potential issue(s). "
                f"Primary root cause: {top_hypo.title} (Confidence: {int(top_hypo.confidence * 100)}%)."
            )

        return DiagnosticReport(
            target_url=target_url,
            execution_time_ms=execution_time_ms,
            layers=layers,
            all_evidence=all_evidence,
            hypotheses=candidates,
            top_hypothesis=top_hypo,
            is_healthy=is_healthy,
            executive_summary=summary,
        )

    # --------------------------------------------------------------------------
    # Individual Rule Evaluators
    # --------------------------------------------------------------------------

    def _evaluate_sg_block(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        tcp_res = layers.get("tcp")
        dns_res = layers.get("dns")
        http_res = layers.get("http")

        if not tcp_res:
            return None

        # Key signature: DNS succeeds, but TCP times out without RST
        tcp_state = tcp_res.metadata.get("state")
        dns_ok = dns_res and dns_res.status == CheckStatus.OK

        if tcp_state == "TIMEOUT" and dns_ok:
            supporting = [
                "DNS successfully resolved target IP address.",
                f"TCP connect to {tcp_res.metadata.get('host')}:{tcp_res.metadata.get('port')} TIMED OUT after SYN transmission.",
                "Zero response received: no SYN-ACK (service) and no RST (rejection). Silent packet drop observed.",
            ]
            if http_res and http_res.status == CheckStatus.FAIL:
                supporting.append("HTTP transaction failed to initiate due to underlying TCP connection hang.")

            return Hypothesis(
                fault_type="01_sg_block",
                title="Firewall / Security Group Dropping Traffic (Port Blocked)",
                confidence=0.96,
                severity="SEV-1",
                category="Network",
                root_cause=(
                    "An inbound firewall rule, AWS Security Group, or iptables DROP policy is blocking traffic "
                    f"to port {tcp_res.metadata.get('port')}. Packets are dropped silently rather than rejected with RST."
                ),
                supporting_evidence=supporting,
                contradicting_evidence=["If service was down without firewall, TCP stack would respond with ECONNREFUSED (RST)."],
                next_best_command=(
                    f"nc -zv -w 3 {tcp_res.metadata.get('host')} {tcp_res.metadata.get('port')} "
                    "&& curl -vvv --connect-timeout 5 {target_url} "
                    "|| (iptables -L -n -v | grep DROP)"
                ),
                remediation_summary=(
                    f"Inspect and update Security Group inbound rules / iptables to allow ingress on port {tcp_res.metadata.get('port')} "
                    "from the client subnet."
                ),
            )
        return None

    def _evaluate_ingress_down(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        tcp_res = layers.get("tcp")
        if not tcp_res:
            return None

        state = tcp_res.metadata.get("state")
        port = tcp_res.metadata.get("port", 80)
        host = tcp_res.metadata.get("host", "127.0.0.1")

        if state == "CONNECTION_REFUSED":
            return Hypothesis(
                fault_type="ingress_service_down",
                title=f"Ingress Web Server Down / Not Listening on Port {port} (TCP RST Refused)",
                confidence=0.96,
                severity="SEV-1",
                category="Application",
                root_cause=(
                    f"Host {host} is reachable on the network, but the ingress web server process (Nginx) is stopped, "
                    f"crashed, or not bound to TCP port {port}. The OS kernel returned an explicit TCP RST packet."
                ),
                supporting_evidence=[
                    f"TCP 3-way handshake to {host}:{port} was rejected with ECONNREFUSED.",
                    "Port is closed; no listening socket exists on the destination host.",
                    "Host network stack is active (RST returned immediately rather than timing out).",
                ],
                contradicting_evidence=["If firewall was blocking traffic, connection would time out without RST."],
                next_best_command=f"docker ps -a --filter name=triageforge-nginx && docker logs triageforge-nginx --tail 30 || ss -tulpn | grep :{port}",
                remediation_summary=f"Start or restart the ingress web server: 'docker start triageforge-nginx' or 'systemctl restart nginx'.",
            )
        return None

    def _evaluate_gunicorn_down(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        http_res = layers.get("http")
        tcp_res = layers.get("tcp")
        host_res = layers.get("host")

        if not http_res:
            return None

        status_code = http_res.metadata.get("status_code")
        server = http_res.metadata.get("server", "").lower()

        # Nginx 502 Bad Gateway
        if status_code == 502:
            supporting = [
                f"HTTP response returned 502 Bad Gateway (Server: {http_res.metadata.get('server')}).",
                "Reverse proxy (Nginx) is alive and accepting connections on port 80/443.",
                "Proxy failed to establish upstream connection to Gunicorn/FastAPI worker socket or port 8000.",
            ]
            if host_res:
                app_status = host_res.metadata.get("container_triageforge-app_status")
                if app_status and app_status != "running":
                    supporting.append(f"Application container 'triageforge-app' status is '{app_status}'.")

            return Hypothesis(
                fault_type="02_gunicorn_down",
                title="Upstream Application Process Down (Nginx 502 Bad Gateway)",
                confidence=0.97,
                severity="SEV-2",
                category="Application",
                root_cause=(
                    "The upstream WSGI/ASGI application (Gunicorn/FastAPI) has crashed, stopped, or is not listening "
                    "on the target port/socket. Nginx received ECONNREFUSED from the upstream backend."
                ),
                supporting_evidence=supporting,
                contradicting_evidence=[],
                next_best_command=(
                    "docker logs triageforge-nginx --tail 25 | grep -i 'connect() failed' "
                    "&& docker ps -a --filter name=triageforge-app "
                    "&& docker logs triageforge-app --tail 40"
                ),
                remediation_summary="Restart the application server process (Gunicorn) or inspect traceback in application logs.",
            )
        return None

    def _evaluate_disk_full(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        host_res = layers.get("host")
        http_res = layers.get("http")

        disk_crit = False
        inode_crit = False
        evidence_found = []

        if host_res:
            pct_used = host_res.metadata.get("disk_pct_used", 0)
            free_gb = host_res.metadata.get("disk_free_gb", 100)
            inode_pct = host_res.metadata.get("inode_pct_used", 0)

            if pct_used > 95.0 or free_gb < 0.2:
                disk_crit = True
                evidence_found.append(f"Host disk utilization is at {pct_used:.1f}% with {free_gb:.2f}GB remaining.")

            if inode_pct > 95.0:
                inode_crit = True
                evidence_found.append(f"Host inode utilization is at {inode_pct:.1f}% (inode table exhausted).")

        # Check HTTP response body signature
        if http_res:
            for ev in http_res.evidence:
                if ev.metric == "signature_disk_full":
                    disk_crit = True
                    evidence_found.append(ev.message)

        if disk_crit or inode_crit:
            sub = "Inode Table Exhausted" if inode_crit and not disk_crit else "Disk Full (No space left on device)"
            return Hypothesis(
                fault_type="03_disk_full",
                title=f"Storage Exhaustion: {sub}",
                confidence=0.98,
                severity="SEV-1",
                category="Storage",
                root_cause=(
                    "The filesystem has run out of storage space or free inodes. "
                    "Unrotated application/web server logs or runaway temp files have consumed available blocks, "
                    "preventing new writes and causing application crashes."
                ),
                supporting_evidence=evidence_found,
                contradicting_evidence=[],
                next_best_command="df -h && df -i && du -sh /var/log/* 2>/dev/null | sort -hr | head -n 10 && lsof +L1",
                remediation_summary="Truncate overgrown log files, enable logrotate, and terminate open deleted file handles (lsof +L1).",
            )
        return None

    def _evaluate_pg_connections(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        host_res = layers.get("host")
        http_res = layers.get("http")

        pg_exhausted = False
        supporting = []

        if host_res:
            for ev in host_res.evidence:
                if ev.metric == "pg_connection_exhaustion":
                    pg_exhausted = True
                    supporting.append(ev.message)

        if http_res:
            for ev in http_res.evidence:
                if ev.metric == "signature_db_exhausted":
                    pg_exhausted = True
                    supporting.append(ev.message)

        if pg_exhausted:
            return Hypothesis(
                fault_type="04_pg_connections",
                title="PostgreSQL Connection Exhaustion ('too many clients already')",
                confidence=0.98,
                severity="SEV-1",
                category="Database",
                root_cause=(
                    "PostgreSQL has reached its max_connections ceiling. Connection leaks in application code "
                    "or absence of a connection pooler (e.g. PgBouncer) have saturated all connection slots."
                ),
                supporting_evidence=supporting,
                contradicting_evidence=[],
                next_best_command=(
                    "docker exec triageforge-db psql -U forge_user -d triageforge -c "
                    "\"SELECT pid, usename, state, age(clock_timestamp(), query_start), query FROM pg_stat_activity WHERE state != 'idle';\""
                ),
                remediation_summary="Terminate idle/leaked sessions with pg_terminate_backend(), increase max_connections, or deploy PgBouncer.",
            )
        return None

    def _evaluate_missing_route(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        tcp_res = layers.get("tcp")
        if not tcp_res:
            return None

        state = tcp_res.metadata.get("state")
        if state in ("HOST_UNREACHABLE", "NETWORK_UNREACHABLE"):
            return Hypothesis(
                fault_type="05_missing_route",
                title="Missing Network Route / Internet Gateway Egress Blackhole",
                confidence=0.94,
                severity="SEV-1",
                category="Network",
                root_cause="Operating system routing table lacks a default gateway route (0.0.0.0/0) or subnet route table missing IGW target.",
                supporting_evidence=[
                    f"TCP socket failed with {state}.",
                    "Kernel network stack reported no route to destination host.",
                ],
                contradicting_evidence=[],
                next_best_command="ip route show && ip neigh show && traceroute -n -m 5 8.8.8.8",
                remediation_summary="Restore default route via 'ip route add default via <gateway_ip>' or re-attach Internet Gateway in AWS VPC route table.",
            )
        return None

    def _evaluate_bad_dns(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        dns_res = layers.get("dns")
        if not dns_res or dns_res.status != CheckStatus.FAIL:
            return None

        return Hypothesis(
            fault_type="06_bad_dns",
            title="DNS Resolution Failure (NXDOMAIN / Nameserver Unreachable)",
            confidence=0.99,
            severity="SEV-1",
            category="Network",
            root_cause=(
                f"Failed to resolve hostname '{dns_res.metadata.get('hostname')}'. "
                f"Details: {dns_res.error_message or 'No address associated with hostname'}."
            ),
            supporting_evidence=[e.message for e in dns_res.evidence if e.status == CheckStatus.FAIL],
            contradicting_evidence=[],
            next_best_command=f"dig +trace {dns_res.metadata.get('hostname')} && cat /etc/resolv.conf && resolvectl status",
            remediation_summary="Fix /etc/resolv.conf nameservers (e.g. 1.1.1.1, 8.8.8.8) or register the missing DNS A record in Route 53.",
        )

    def _evaluate_tls_failure(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        tls_res = layers.get("tls")
        if not tls_res or tls_res.status == CheckStatus.SKIPPED:
            return None

        expired = False
        mismatch = False
        reasons = []

        for ev in tls_res.evidence:
            if ev.metric == "cert_expiry" and ev.status == CheckStatus.FAIL:
                expired = True
                reasons.append(ev.message)
            elif ev.metric == "cert_hostname_mismatch":
                mismatch = True
                reasons.append(ev.message)
            elif ev.metric == "cert_trust_chain":
                reasons.append(ev.message)

        if expired or mismatch or tls_res.status == CheckStatus.FAIL:
            title_detail = "Expired Certificate" if expired else ("Hostname SAN Mismatch" if mismatch else "Untrusted Certificate Chain")
            return Hypothesis(
                fault_type="07_expired_tls",
                title=f"TLS/SSL Certificate Failure ({title_detail})",
                confidence=0.96,
                severity="SEV-2",
                category="Security",
                root_cause=f"TLS handshake rejected: {'; '.join(reasons)}",
                supporting_evidence=reasons,
                contradicting_evidence=[],
                next_best_command=(
                    f"openssl s_client -connect {tls_res.metadata.get('host')}:{tls_res.metadata.get('port')} "
                    f"-servername {tls_res.metadata.get('host')} -showcerts </dev/null 2>/dev/null "
                    "| openssl x509 -noout -dates -subject -issuer -ext subjectAltName"
                ),
                remediation_summary="Renew expired certificate (Certbot/ACM) or update Subject Alternative Names to match requested host.",
            )
        return None

    def _evaluate_iam_s3_denied(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        http_res = layers.get("http")
        if not http_res:
            return None

        has_iam_evidence = any(e.metric == "signature_iam_denied" for e in http_res.evidence)
        status_code = http_res.metadata.get("status_code")

        if has_iam_evidence or (status_code == 403 and "s3" in http_res.metadata.get("path", "").lower()):
            return Hypothesis(
                fault_type="08_iam_s3_denied",
                title="IAM Role / Storage Permission Denial (S3 AccessDenied 403)",
                confidence=0.95,
                severity="SEV-2",
                category="Security",
                root_cause="The application's IAM execution role or storage credentials lack 's3:GetObject'/'s3:PutObject' permission on the target bucket.",
                supporting_evidence=[
                    "HTTP response returned 403 Forbidden with AWS AccessDenied error payload.",
                    "S3 API rejected request authorization signature.",
                ],
                contradicting_evidence=[],
                next_best_command=(
                    "aws sts get-caller-identity && "
                    "aws s3 ls s3://triageforge-storage-bucket/ || "
                    "grep -i 'AccessDenied' /var/log/app/triageforge.log"
                ),
                remediation_summary="Attach an IAM policy granting s3:GetObject/PutObject for the bucket ARN to the EC2/Task role.",
            )
        return None

    def _evaluate_oom_killer(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        host_res = layers.get("host")
        if not host_res:
            return None

        oom_detected = False
        reasons = []

        for ev in host_res.evidence:
            if ev.metric in ("container_oom_kill", "kernel_oom_killer"):
                oom_detected = True
                reasons.append(ev.message)

        if oom_detected:
            return Hypothesis(
                fault_type="09_oom_killed",
                title="Linux Kernel OOM Killer Invocation (Exit Code 137 / Memory Saturation)",
                confidence=0.99,
                severity="SEV-1",
                category="Compute",
                root_cause=(
                    "A runaway memory leak or undersized container memory limit triggered the Linux kernel "
                    "Out-Of-Memory (OOM) killer. The kernel sent SIGKILL (exit 137) to the application worker process."
                ),
                supporting_evidence=reasons,
                contradicting_evidence=[],
                next_best_command=(
                    "dmesg -T | grep -i -E 'oom[-_]killer|killed process' | tail -n 25 "
                    "&& docker inspect --format '{{.State.OOMKilled}} (Exit: {{.State.ExitCode}})' triageforge-app"
                ),
                remediation_summary="Profile application heap allocations (tracemalloc/valgrind), fix memory leak, and increase cgroup memory limit.",
            )
        return None

    def _evaluate_ssh_lockout(self, layers: Dict[str, LayerResult]) -> Optional[Hypothesis]:
        # Evaluated if host/ssh probe was run
        host_res = layers.get("host")
        if not host_res:
            return None

        for ev in host_res.evidence:
            if "ssh_lockout" in ev.metric or "ssh_permission" in ev.metric:
                return Hypothesis(
                    fault_type="10_ssh_lockout",
                    title="SSH Lockout / Key File Permission or Daemon Config Rejection",
                    confidence=0.95,
                    severity="SEV-1",
                    category="Security",
                    root_cause="OpenSSH daemon rejected connection because ~/.ssh or authorized_keys permissions are too open (e.g. 777), or sshd_config is misconfigured.",
                    supporting_evidence=[ev.message],
                    contradicting_evidence=[],
                    next_best_command="ssh -vvv -o BatchMode=yes -o StrictHostKeyChecking=no forge_admin@localhost -p 2222",
                    remediation_summary="chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && chown -R forge_admin:forge_admin ~/.ssh",
                )
        return None
