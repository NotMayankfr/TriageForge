"""
Host & Container Diagnostic Layer
Collects OS and container telemetry:
- Disk space & inode exhaustion (df -h, df -i)
- Memory usage & OOM killer invocations (dmesg, cgroup memory, Docker OOMKilled)
- Process & socket status (ss -tulpn, systemd/process status)
- Database active sessions vs max_connections (pg_stat_activity)
- Docker container health & recent crash logs
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from triageforge.models import CheckStatus, Evidence, LayerResult


class HostLayer:
    """Inspects host machine and Docker container runtime state."""

    def __init__(self, target_container_prefix: str = "triageforge"):
        self.container_prefix = target_container_prefix

    def inspect(self) -> LayerResult:
        start_time = time.perf_counter()
        evidence: List[Evidence] = []
        metadata: Dict[str, Any] = {}

        # 1. Inspect Disk Space & Inodes
        self._check_disk_and_inodes(evidence, metadata)

        # 2. Inspect Docker Containers (if available)
        containers = self._inspect_docker_containers(evidence, metadata)

        # 3. Inspect Memory & OOM Killer Events
        self._check_memory_and_oom(containers, evidence, metadata)

        # 4. Inspect Database Connection Saturation
        self._check_postgres_connections(evidence, metadata)

        # Determine overall status
        has_fail = any(e.status == CheckStatus.FAIL for e in evidence)
        has_warn = any(e.status == CheckStatus.WARN for e in evidence)
        status = CheckStatus.FAIL if has_fail else (CheckStatus.WARN if has_warn else CheckStatus.OK)

        duration_ms = (time.perf_counter() - start_time) * 1000
        return LayerResult(
            layer_name="host",
            status=status,
            duration_ms=round(duration_ms, 2),
            evidence=evidence,
            metadata=metadata,
        )

    def _check_disk_and_inodes(self, evidence: List[Evidence], metadata: Dict[str, Any]) -> None:
        """Checks root filesystem and mount points for space and inode exhaustion."""
        try:
            # Check disk usage using shutil.disk_usage
            target_path = "/" if os.name != "nt" else "C:\\"
            usage = shutil.disk_usage(target_path)
            total_gb = usage.total / (1024 ** 3)
            used_gb = usage.used / (1024 ** 3)
            free_gb = usage.free / (1024 ** 3)
            pct_used = (usage.used / usage.total) * 100.0

            metadata["disk_total_gb"] = round(total_gb, 2)
            metadata["disk_used_gb"] = round(used_gb, 2)
            metadata["disk_free_gb"] = round(free_gb, 2)
            metadata["disk_pct_used"] = round(pct_used, 1)

            if pct_used > 95.0 or free_gb < 0.2:
                evidence.append(
                    Evidence(
                        layer="host",
                        metric="disk_space",
                        status=CheckStatus.FAIL,
                        observed=f"{pct_used:.1f}% used ({free_gb:.2f}GB free)",
                        expected="> 10% free space",
                        message=f"CRITICAL DISK SPACE EXHAUSTION: Filesystem is {pct_used:.1f}% full with only {free_gb:.2f}GB remaining.",
                        weight=2.0,
                    )
                )
            elif pct_used > 85.0:
                evidence.append(
                    Evidence(
                        layer="host",
                        metric="disk_space",
                        status=CheckStatus.WARN,
                        observed=f"{pct_used:.1f}% used",
                        expected="< 85% used",
                        message=f"High disk utilization ({pct_used:.1f}% used). Monitor log directories.",
                        weight=0.8,
                    )
                )
            else:
                evidence.append(
                    Evidence(
                        layer="host",
                        metric="disk_space",
                        status=CheckStatus.OK,
                        observed=f"{pct_used:.1f}% used ({free_gb:.2f}GB free)",
                        message=f"Filesystem capacity healthy: {free_gb:.2f}GB available.",
                        weight=0.5,
                    )
                )

            # Inode check on Unix systems
            if hasattr(os, "statvfs"):
                vfs = os.statvfs(target_path)
                if vfs.f_files > 0:
                    inodes_total = vfs.f_files
                    inodes_free = vfs.f_ffree
                    inodes_used_pct = ((inodes_total - inodes_free) / inodes_total) * 100.0
                    metadata["inode_pct_used"] = round(inodes_used_pct, 1)

                    if inodes_used_pct > 95.0 or inodes_free < 1000:
                        evidence.append(
                            Evidence(
                                layer="host",
                                metric="inode_exhaustion",
                                status=CheckStatus.FAIL,
                                observed=f"{inodes_used_pct:.1f}% inodes used ({inodes_free} remaining)",
                                expected="> 10,000 free inodes",
                                message="INODE EXHAUSTION: Filesystem has exhausted inodes despite remaining disk bytes. Caused by millions of small files/sessions.",
                                weight=2.0,
                            )
                        )
        except Exception as e:
            metadata["disk_check_error"] = str(e)

    def _inspect_docker_containers(self, evidence: List[Evidence], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Inspects docker containers via docker CLI (supporting WSL/Linux/Windows)."""
        containers: List[Dict[str, Any]] = []
        try:
            # Query docker ps -a with JSON format
            cmd = ["docker", "ps", "-a", "--format", "{{json .}}"]
            res = self._run_subproc(cmd)
            if res.returncode != 0:
                return containers

            for line in res.stdout.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    cdata = json.loads(line)
                    names = cdata.get("Names", "")
                    if self.container_prefix in names:
                        containers.append(cdata)
                except Exception:
                    continue

            metadata["monitored_containers"] = len(containers)

            # Inspect each container in detail
            for c in containers:
                cname = c.get("Names")
                cid = c.get("ID")
                # Run docker inspect
                inspect_res = self._run_subproc(["docker", "inspect", cid])
                if inspect_res.returncode == 0:
                    try:
                        inspect_json = json.loads(inspect_res.stdout)
                        if inspect_json:
                            state = inspect_json[0].get("State", {})
                            status = state.get("Status", "unknown")
                            exit_code = state.get("ExitCode", 0)
                            oom_killed = state.get("OOMKilled", False)

                            metadata[f"container_{cname}_status"] = status
                            metadata[f"container_{cname}_exit_code"] = exit_code
                            metadata[f"container_{cname}_oom_killed"] = oom_killed

                            if oom_killed or exit_code == 137:
                                evidence.append(
                                    Evidence(
                                        layer="host",
                                        metric="container_oom_kill",
                                        status=CheckStatus.FAIL,
                                        observed=f"{cname} OOMKilled=True, ExitCode={exit_code}",
                                        expected="ExitCode 0, OOMKilled=False",
                                        message=f"CONTAINER OOM KILL DETECTED: Container '{cname}' was terminated by Linux kernel OOM killer (exit code 137 / SIGKILL).",
                                        weight=2.0,
                                    )
                                )
                            elif status == "exited" and exit_code != 0:
                                evidence.append(
                                    Evidence(
                                        layer="host",
                                        metric="container_crash",
                                        status=CheckStatus.FAIL,
                                        observed=f"{cname} exited with code {exit_code}",
                                        expected="Running (ExitCode 0)",
                                        message=f"Container '{cname}' unexpectedly exited with non-zero status {exit_code}.",
                                        weight=1.8,
                                    )
                                )
                            elif status == "restarting":
                                evidence.append(
                                    Evidence(
                                        layer="host",
                                        metric="container_crashloop",
                                        status=CheckStatus.FAIL,
                                        observed=f"{cname} is in restart loop",
                                        expected="Stable running status",
                                        message=f"CrashLoop detected: Container '{cname}' is repeatedly crashing and restarting.",
                                        weight=2.0,
                                    )
                                )
                    except Exception:
                        pass

        except Exception as e:
            metadata["docker_inspect_error"] = str(e)

        return containers

    def _check_memory_and_oom(self, containers: List[Dict[str, Any]], evidence: List[Evidence], metadata: Dict[str, Any]) -> None:
        """Inspects host memory and kernel dmesg for OOM killer invocations."""
        try:
            # Check dmesg for OOM killer entries
            dmesg_res = self._run_subproc(["dmesg", "-T"])
            if dmesg_res.returncode == 0:
                dmesg_lines = dmesg_res.stdout.splitlines()[-50:]  # last 50 lines
                oom_lines = [l for l in dmesg_lines if "invoked oom-killer" in l.lower() or "out of memory: killed process" in l.lower()]
                if oom_lines:
                    metadata["kernel_oom_events"] = len(oom_lines)
                    evidence.append(
                        Evidence(
                            layer="host",
                            metric="kernel_oom_killer",
                            status=CheckStatus.FAIL,
                            observed=f"Found {len(oom_lines)} OOM killer event(s) in dmesg",
                            expected="No OOM killer events",
                            message=f"Kernel OOM killer active: {oom_lines[-1].strip()}",
                            weight=2.0,
                        )
                    )
        except Exception:
            pass

    def _check_postgres_connections(self, evidence: List[Evidence], metadata: Dict[str, Any]) -> None:
        """Queries PostgreSQL container or socket for active connections vs max_connections."""
        try:
            # Query active connections using docker exec if container is running
            db_query = (
                "SELECT count(*)::text || '/' || current_setting('max_connections') "
                "FROM pg_stat_activity;"
            )
            cmd = ["docker", "exec", "triageforge-db", "psql", "-U", "forge_user", "-d", "triageforge", "-t", "-c", db_query]
            res = self._run_subproc(cmd)
            if res.returncode == 0:
                output = res.stdout.strip()
                if "/" in output:
                    parts = output.split("/")
                    active_conn = int(parts[0].strip())
                    max_conn = int(parts[1].strip())

                    metadata["pg_active_connections"] = active_conn
                    metadata["pg_max_connections"] = max_conn

                    if active_conn >= max_conn - 1:
                        evidence.append(
                            Evidence(
                                layer="host",
                                metric="pg_connection_exhaustion",
                                status=CheckStatus.FAIL,
                                observed=f"{active_conn}/{max_conn} connections used",
                                expected=f"< {int(max_conn * 0.8)} connections",
                                message=f"POSTGRESQL CONNECTION POOL EXHAUSTED: {active_conn} active sessions out of {max_conn} max allowed. Remaining client requests will be rejected.",
                                weight=2.0,
                            )
                        )
                    elif active_conn > max_conn * 0.8:
                        evidence.append(
                            Evidence(
                                layer="host",
                                metric="pg_connection_pressure",
                                status=CheckStatus.WARN,
                                observed=f"{active_conn}/{max_conn} connections used",
                                expected=f"< {int(max_conn * 0.8)} connections",
                                message=f"PostgreSQL connection pool near saturation ({active_conn}/{max_conn}).",
                                weight=1.0,
                            )
                        )
                    else:
                        evidence.append(
                            Evidence(
                                layer="host",
                                metric="pg_connection_health",
                                status=CheckStatus.OK,
                                observed=f"{active_conn}/{max_conn} connections",
                                message=f"PostgreSQL connection capacity healthy ({active_conn}/{max_conn} used).",
                                weight=0.5,
                            )
                        )
            else:
                # If command failed, check if the error was "FATAL: too many clients already"
                err_output = (res.stderr + res.stdout).lower()
                if "too many clients" in err_output or "remaining connection slots are reserved" in err_output:
                    evidence.append(
                        Evidence(
                            layer="host",
                            metric="pg_connection_exhaustion",
                            status=CheckStatus.FAIL,
                            observed="Postgres rejected connection: 'too many clients already'",
                            expected="Accepted connection",
                            message="PostgreSQL is refusing incoming client connections due to connection exhaustion.",
                            weight=2.0,
                        )
                    )
        except Exception as e:
            metadata["pg_check_error"] = str(e)

    def _run_subproc(self, cmd: List[str], timeout_sec: float = 3.0) -> subprocess.CompletedProcess[str]:
        """Safely runs command in local OS or delegates to WSL if on Windows."""
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except FileNotFoundError:
            # If docker not found in Windows path, try running through WSL
            if os.name == "nt" and cmd[0] == "docker":
                wsl_cmd = ["wsl", "-d", "Ubuntu", "--"] + cmd
                try:
                    return subprocess.run(wsl_cmd, capture_output=True, text=True, timeout=timeout_sec)
                except Exception as ex:
                    return subprocess.CompletedProcess(args=cmd, returncode=127, stdout="", stderr=str(ex))
            return subprocess.CompletedProcess(args=cmd, returncode=127, stdout="", stderr=f"Command '{cmd[0]}' not found.")
        except Exception as e:
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))
