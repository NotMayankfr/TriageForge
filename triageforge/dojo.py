"""
TriageForge Dojo: Interactive Incident Training & SRE Drill Simulator
Enables engineers to train on simulated customer outages with progressive hints,
time tracking, and diagnostic evaluation.
"""

from __future__ import annotations
import json
import os
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DOJO_STATE_FILE = Path(".triageforge_dojo.json")
FAULTS_DIR = Path(__file__).resolve().parent.parent / "faults"

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "01_sg_block": {
        "title": "Silent Ingress Timeout on Payment Webhook",
        "severity": "SEV-1",
        "customer_report": (
            "Partner bank systems are unable to deliver payment webhooks to https://api.triageforge.local/api/items. "
            "Their monitoring indicates connections are hanging indefinitely and timing out after 30 seconds. "
            "Our internal web servers show no incoming HTTP logs for these requests."
        ),
        "hints": [
            "Level 1: Run 'triageforge diagnose'. Pay close attention to Layer 2 (TCP handshake) vs Layer 1 (DNS).",
            "Level 2: The socket is experiencing TIMEOUT, not ECONNREFUSED. Check packet filtering / security group ingress rules.",
            "Level 3: A firewall rule or Security Group is silently dropping incoming SYN packets to port 80/443 without emitting RST.",
        ],
    },
    "02_gunicorn_down": {
        "title": "Intermittent HTTP 502 Bad Gateway Spikes",
        "severity": "SEV-2",
        "customer_report": (
            "Frontend users are receiving '502 Bad Gateway' error pages when querying the loan underwriting directory. "
            "Nginx access logs show elevated 502 status codes, but the host CPU and memory utilization appear normal."
        ),
        "hints": [
            "Level 1: An HTTP 502 indicates the reverse proxy cannot communicate with its configured upstream backend.",
            "Level 2: Check listening sockets on 127.0.0.1:8000 or inspect 'docker logs triageforge-nginx'.",
            "Level 3: The Gunicorn/FastAPI application container has crashed or terminated, causing Nginx to receive ECONNREFUSED from 127.0.0.1:8000.",
        ],
    },
    "03_disk_full": {
        "title": "Database Writes Failing with Storage I/O Errors",
        "severity": "SEV-1",
        "customer_report": (
            "Application background workers are aborting tasks with 500 errors. "
            "Customer uploads are rejected with 'failed to write temporary file'. Database writes are completely stalled."
        ),
        "hints": [
            "Level 1: Run 'df -h' and 'df -i' to inspect storage mounts and inode table utilization.",
            "Level 2: Unrotated log files or runaway batch output have saturated available disk blocks or inode structures.",
            "Level 3: Filesystem is at 100% capacity (ENOSPC). Check /var/log/app for large runaway logs.",
        ],
    },
    "04_pg_connections": {
        "title": "Cascading HTTP 500s from Database Connection Saturation",
        "severity": "SEV-1",
        "customer_report": (
            "All user requests requiring database reads or writes are returning HTTP 500 errors. "
            "Application logs display: 'FATAL: too many clients already'."
        ),
        "hints": [
            "Level 1: The database client error points to connection pool exhaustion.",
            "Level 2: Connect to PostgreSQL and query 'pg_stat_activity' to count active vs max_connections.",
            "Level 3: Idle-in-transaction connections or lack of connection pooling have consumed all 20 connection slots.",
        ],
    },
    "05_missing_route": {
        "title": "Backend Outbound Calls Failing with Network Unreachable",
        "severity": "SEV-1",
        "customer_report": (
            "The backend application is unable to reach third-party identity verification APIs. "
            "Internal network calls throw 'Network is unreachable' (EHOSTUNREACH) immediately without DNS resolution failure."
        ),
        "hints": [
            "Level 1: Check the local routing table with 'ip route show'.",
            "Level 2: The container or instance network interface lacks a default gateway (0.0.0.0/0).",
            "Level 3: Outbound egress traffic cannot find a next-hop gateway router. Re-attach the default route or network bridge.",
        ],
    },
    "06_bad_dns": {
        "title": "Complete Service Disruption: Nameserver Failure",
        "severity": "SEV-1",
        "customer_report": (
            "All microservice calls are failing instantly with 'Could not resolve host' / gaierror. "
            "Neither internal service names nor public domains can be resolved."
        ),
        "hints": [
            "Level 1: Test DNS resolution directly with 'dig' or 'getaddrinfo'.",
            "Level 2: Inspect /etc/resolv.conf and systemd-resolved configuration.",
            "Level 3: Nameserver IP is pointing to a non-responsive address (198.51.100.1).",
        ],
    },
    "07_expired_tls": {
        "title": "Browser Red Screen Security Warnings on HTTPS Gateway",
        "severity": "SEV-2",
        "customer_report": (
            "Clients navigating to https://triageforge.local are met with browser warnings: "
            "'Your connection is not private' (NET::ERR_CERT_DATE_INVALID). Automated curl jobs fail with exit code 60."
        ),
        "hints": [
            "Level 1: Run 'openssl s_client -connect localhost:443 -servername triageforge.local'.",
            "Level 2: Check the certificate 'notAfter' timestamp vs current UTC time.",
            "Level 3: The TLS certificate active on Nginx expired 30 days ago. Rotate with valid certificate.",
        ],
    },
    "08_iam_s3_denied": {
        "title": "Document Storage Service Rejecting Uploads with 403",
        "severity": "SEV-2",
        "customer_report": (
            "Users attempting to download compliance attachments receive HTTP 403 Forbidden. "
            "Application response headers indicate an AWS AccessDenied error XML body."
        ),
        "hints": [
            "Level 1: Inspect the response payload from /api/s3-check.",
            "Level 2: The mock S3 storage API returned 403 with <Code>AccessDenied</Code>.",
            "Level 3: Application IAM execution role or storage policy lacks 's3:GetObject' permission.",
        ],
    },
    "09_oom_killed": {
        "title": "Application Worker Abruptly Disappearing under Load",
        "severity": "SEV-1",
        "customer_report": (
            "During burst traffic, the application service terminates silently and restarts. "
            "The process exits with status code 137 without writing Python tracebacks to application logs."
        ),
        "hints": [
            "Level 1: An exit code of 137 indicates 128 + 9 (SIGKILL).",
            "Level 2: Check 'dmesg -T' for kernel Out-Of-Memory killer messages or 'docker inspect' for OOMKilled.",
            "Level 3: Memory leak exceeded the 300MB container memory limit, prompting the Linux kernel to send SIGKILL.",
        ],
    },
    "10_ssh_lockout": {
        "title": "On-Call Bastion Emergency Access Locked Out",
        "severity": "SEV-1",
        "customer_report": (
            "During an escalation, DevOps engineers attempting to SSH into the bastion receive: "
            "'Permission denied (publickey)'. The private key is known to be correct."
        ),
        "hints": [
            "Level 1: Run 'ssh -vvv' to inspect client-server authentication negotiation.",
            "Level 2: OpenSSH enforces 'StrictModes' by default, checking file permissions on ~/.ssh and authorized_keys.",
            "Level 3: Permissions on ~/.ssh/authorized_keys or ~/.ssh are too loose (e.g. 777). Must be chmod 700 and 600.",
        ],
    },
}


class DojoManager:
    """Manages SRE incident training drill lifecycle."""

    def __init__(self, state_file: Path = DOJO_STATE_FILE):
        self.state_file = state_file

    def start_drill(self, fault_id: Optional[str] = None) -> Dict[str, Any]:
        if self.is_drill_active():
            active = self.get_active_session()
            raise RuntimeError(f"A drill is already in progress (Fault: {active['fault_id']}). Run 'triageforge dojo stop' or 'submit' first.")

        if not fault_id:
            fault_id = random.choice(list(SCENARIOS.keys()))
        elif fault_id not in SCENARIOS:
            raise ValueError(f"Unknown fault ID: {fault_id}. Choose from: {', '.join(SCENARIOS.keys())}")

        scenario = SCENARIOS[fault_id]
        fault_dir = FAULTS_DIR / fault_id
        break_script = fault_dir / "break.sh"

        if not break_script.exists():
            raise FileNotFoundError(f"Missing break.sh at {break_script}")

        # Inject the fault silently
        self._run_script(break_script)

        # Record session state
        session = {
            "fault_id": fault_id,
            "title": scenario["title"],
            "severity": scenario["severity"],
            "start_time": datetime.now(timezone.utc).isoformat(),
            "hints_used": 0,
            "attempts": 0,
        }
        self.state_file.write_text(json.dumps(session, indent=2), encoding="utf-8")

        return {
            "fault_id": fault_id,
            "title": scenario["title"],
            "severity": scenario["severity"],
            "customer_report": scenario["customer_report"],
        }

    def get_hint(self) -> str:
        session = self.get_active_session()
        if not session:
            raise RuntimeError("No active drill in progress. Start one with 'triageforge dojo start'.")

        fault_id = session["fault_id"]
        hints = SCENARIOS[fault_id]["hints"]
        idx = session["hints_used"]

        if idx >= len(hints):
            return "No more hints available! You have received all 3 progressive hints."

        hint = hints[idx]
        session["hints_used"] += 1
        self.state_file.write_text(json.dumps(session, indent=2), encoding="utf-8")
        return hint

    def submit_diagnosis(self, submitted_id: str) -> Dict[str, Any]:
        session = self.get_active_session()
        if not session:
            raise RuntimeError("No active drill in progress. Start one with 'triageforge dojo start'.")

        actual_id = session["fault_id"]
        start_dt = datetime.fromisoformat(session["start_time"])
        elapsed_sec = int((datetime.now(timezone.utc) - start_dt).total_seconds())

        is_correct = submitted_id.strip() == actual_id

        if is_correct:
            # Score formula: 100 - (15 * hints) - (elapsed_sec / 20)
            score = max(15, 100 - (session["hints_used"] * 15) - int(elapsed_sec / 20))
            if score >= 85:
                rank = "Senior Cloud Support Engineer / Principal SRE"
            elif score >= 65:
                rank = "Cloud Support Engineer II"
            else:
                rank = "Cloud Support Associate"

            # Auto-heal the stack
            fix_script = FAULTS_DIR / actual_id / "fix.sh"
            if fix_script.exists():
                self._run_script(fix_script)

            # Cleanup session
            self.state_file.unlink(missing_ok=True)

            return {
                "success": True,
                "fault_id": actual_id,
                "elapsed_seconds": elapsed_sec,
                "hints_used": session["hints_used"],
                "score": score,
                "rank": rank,
                "remediation": f"Stack automatically recovered via {fix_script.name}.",
            }
        else:
            session["attempts"] += 1
            self.state_file.write_text(json.dumps(session, indent=2), encoding="utf-8")
            return {
                "success": False,
                "submitted_id": submitted_id,
                "attempts": session["attempts"],
                "message": (
                    f"Diagnosis '{submitted_id}' is INCORRECT. "
                    "Run 'triageforge diagnose' or request a hint via 'triageforge dojo hint'."
                ),
            }

    def stop_drill(self) -> Optional[str]:
        session = self.get_active_session()
        if not session:
            return None

        actual_id = session["fault_id"]
        fix_script = FAULTS_DIR / actual_id / "fix.sh"
        if fix_script.exists():
            self._run_script(fix_script)

        self.state_file.unlink(missing_ok=True)
        return actual_id

    def is_drill_active(self) -> bool:
        return self.state_file.exists()

    def get_active_session(self) -> Optional[Dict[str, Any]]:
        if not self.state_file.exists():
            return None
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _run_script(self, script_path: Path) -> int:
        posix_path = str(script_path).replace("\\", "/")
        if os.name == "nt":
            cmd = ["wsl", "-d", "Ubuntu", "--", "bash", posix_path]
        else:
            cmd = ["bash", str(script_path)]
        return subprocess.run(cmd, capture_output=True).returncode
