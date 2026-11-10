"""
TriageForge Command Line Interface
The primary engineering tool for automated failure diagnosis, fault injection,
and runbook execution.
"""

from __future__ import annotations
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from triageforge.analyzer.log_analyzer import LogAnalyzer
from triageforge.analyzer.pcap_analyzer import PCAPAnalyzer
from triageforge.aws_checks import check_ec2_cpu_alarm, check_route_table_igw, check_security_group
from triageforge.dojo import DojoManager
from triageforge.engine import DiagnosisEngine
from triageforge.layers.dns_layer import DNSLayer
from triageforge.layers.host_layer import HostLayer
from triageforge.layers.http_layer import HTTPLayer
from triageforge.layers.tcp_layer import TCPLayer
from triageforge.layers.tls_layer import TLSLayer
from triageforge.reporter import ReportRenderer

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="TriageForge")
def main():
    """TriageForge: Deterministic Cloud Failure Triage Lab & SRE Diagnosis Tool."""
    pass


@main.command(name="diagnose")
@click.option("--url", "-u", default="http://localhost:80", help="Target URL or endpoint to diagnose.")
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "markdown", "json"]), default="terminal", help="Report output format.")
@click.option("--output", "-o", type=click.Path(writable=True), default=None, help="Save report to specified file.")
@click.option("--aws-sg", default=None, help="Optional AWS Security Group ID to inspect.")
@click.option("--aws-rt", default=None, help="Optional AWS Route Table ID to inspect.")
@click.option("--aws-instance", default=None, help="Optional EC2 Instance ID to inspect.")
@click.option("--timeout", "-t", default=5.0, type=float, help="Socket and HTTP timeout in seconds.")
def diagnose_command(
    url: str,
    output_format: str,
    output: Optional[str],
    aws_sg: Optional[str],
    aws_rt: Optional[str],
    aws_instance: Optional[str],
    timeout: float,
):
    """Diagnose a failure by probing bottom-up through the network, host, and app layers."""
    start_time = time.perf_counter()

    if output_format == "terminal":
        with console.status(f"[bold cyan]TriageForge probing target: {url} ...[/bold cyan]", spinner="dots"):
            layers = _run_all_layers(url, timeout, aws_sg, aws_rt, aws_instance)
    else:
        layers = _run_all_layers(url, timeout, aws_sg, aws_rt, aws_instance)

    duration_ms = (time.perf_counter() - start_time) * 1000

    engine = DiagnosisEngine()
    report = engine.analyze(target_url=url, layers=layers, execution_time_ms=duration_ms)

    renderer = ReportRenderer(console)

    if output_format == "terminal":
        renderer.render_terminal(report)
    elif output_format == "markdown":
        md_text = renderer.to_markdown(report)
        if output:
            Path(output).write_text(md_text, encoding="utf-8")
            console.print(f"[green]Saved Markdown report to {output}[/green]")
        else:
            click.echo(md_text)
    elif output_format == "json":
        json_text = renderer.to_json(report)
        if output:
            Path(output).write_text(json_text, encoding="utf-8")
            console.print(f"[green]Saved JSON report to {output}[/green]")
        else:
            click.echo(json_text)

    # Return non-zero exit code if incident is active (useful for CI/CD assertions)
    if not report.is_healthy:
        sys.exit(2)


def _run_all_layers(
    url: str,
    timeout: float,
    aws_sg: Optional[str],
    aws_rt: Optional[str],
    aws_instance: Optional[str],
) -> dict:
    """Executes bottom-up layer diagnostics."""
    layers = {}

    # Layer 1: DNS
    dns_probe = DNSLayer(timeout_sec=timeout)
    layers["dns"] = dns_probe.inspect(url)

    # Layer 2: TCP
    tcp_probe = TCPLayer(timeout_sec=timeout)
    layers["tcp"] = tcp_probe.inspect(url)

    # Layer 3: TLS
    tls_probe = TLSLayer(timeout_sec=timeout)
    layers["tls"] = tls_probe.inspect(url)

    # Layer 4: HTTP
    http_probe = HTTPLayer(timeout_sec=timeout)
    layers["http"] = http_probe.inspect(url)

    # Layer 5: Host & Container
    host_probe = HostLayer()
    layers["host"] = host_probe.inspect()

    # Layer 6: AWS checks (if specified)
    if aws_sg:
        layers["aws_sg"] = check_security_group(group_id=aws_sg)
    if aws_rt:
        layers["aws_route"] = check_route_table_igw(route_table_id=aws_rt)
    if aws_instance:
        layers["aws_ec2"] = check_ec2_cpu_alarm(instance_id=aws_instance)

    return layers


@main.command(name="list-faults")
def list_faults_command():
    """List all 10 realistic failure scenarios in the TriageForge catalog."""
    table = Table(title="TriageForge Failure Catalog", header_style="bold cyan", border_style="dim")
    table.add_column("ID", style="bold yellow", width=18)
    table.add_column("Category", style="cyan", width=12)
    table.add_column("Symptom", style="white")
    table.add_column("Primary Diagnostic Metric", style="green")

    scenarios = [
        ("01_sg_block", "Network", "curl hangs (TCP timeout, not connection refused)", "TCP handshake timeout (no SYN-ACK/RST)"),
        ("02_gunicorn_down", "Application", "Nginx responds with HTTP 502 Bad Gateway", "Upstream 127.0.0.1:8000 connection refused"),
        ("03_disk_full", "Storage", "HTTP 500 / 'No space left on device'", "Filesystem % used > 95% / Inode exhaustion"),
        ("04_pg_connections", "Database", "HTTP 500 / 'too many clients already'", "pg_stat_activity active == max_connections"),
        ("05_missing_route", "Network", "Instance/container cannot reach external network", "TCP EHOSTUNREACH / missing 0.0.0.0/0 gateway"),
        ("06_bad_dns", "Network", "Hostname does not resolve (NXDOMAIN / SERVFAIL)", "getaddrinfo / dig failure"),
        ("07_expired_tls", "Security", "SSL certificate verification error / expired", "notAfter timestamp in past / SAN mismatch"),
        ("08_iam_s3_denied", "Security", "HTTP 403 Forbidden / AccessDenied XML", "Missing s3:GetObject / PutObject in IAM policy"),
        ("09_oom_killed", "Compute", "App worker terminates with exit code 137", "Linux kernel OOM killer / cgroup memory limit"),
        ("10_ssh_lockout", "Security", "Permission denied (publickey) / SSH lockout", "Permissions on ~/.ssh not 700 / authorized_keys 600"),
    ]

    for fid, cat, sym, diag in scenarios:
        table.add_row(fid, cat, sym, diag)

    console.print(table)


@main.command(name="inject")
@click.argument("fault_id")
def inject_command(fault_id: str):
    """Inject a realistic fault from the fault library (e.g. 02_gunicorn_down)."""
    fault_dir = _find_fault_dir(fault_id)
    if not fault_dir:
        console.print(f"[bold red]Fault '{fault_id}' not found in faults directory.[/bold red]")
        sys.exit(1)

    break_script = fault_dir / "break.sh"
    if not break_script.exists():
        console.print(f"[bold red]break.sh not found in {fault_dir}[/bold red]")
        sys.exit(1)

    console.print(f"[bold yellow]Injecting fault:[/bold yellow] [bold white]{fault_dir.name}[/bold white] ...")
    ret = _run_script(break_script)
    if ret == 0:
        console.print(f"[bold green][OK] Fault successfully injected.[/bold green] Run [cyan]triageforge diagnose[/cyan] to test.")
    else:
        console.print(f"[bold red][FAIL] Failed to inject fault (exit code {ret}).[/bold red]")
        sys.exit(ret)


@main.command(name="recover")
@click.argument("fault_id")
def recover_command(fault_id: str):
    """Recover the stack by executing fix.sh for the given fault."""
    fault_dir = _find_fault_dir(fault_id)
    if not fault_dir:
        console.print(f"[bold red]Fault '{fault_id}' not found in faults directory.[/bold red]")
        sys.exit(1)

    fix_script = fault_dir / "fix.sh"
    if not fix_script.exists():
        console.print(f"[bold red]fix.sh not found in {fault_dir}[/bold red]")
        sys.exit(1)

    console.print(f"[bold cyan]Recovering fault:[/bold cyan] [bold white]{fault_dir.name}[/bold white] ...")
    ret = _run_script(fix_script)
    if ret == 0:
        console.print(f"[bold green][OK] Stack recovered.[/bold green] Run [cyan]triageforge diagnose[/cyan] to verify.")
    else:
        console.print(f"[bold red][FAIL] Failed to recover fault (exit code {ret}).[/bold red]")
        sys.exit(ret)


# ------------------------------------------------------------------------------
# Incident Training Drill Mode ("Dojo")
# ------------------------------------------------------------------------------

@main.group(name="dojo")
def dojo_group():
    """Interactive Incident Training Dojo for SREs and Cloud Support Engineers."""
    pass


@dojo_group.command(name="start")
@click.option("--fault", "-f", "fault_id", default=None, help="Specific fault scenario ID to practice against (e.g. 02_gunicorn_down).")
def dojo_start_command(fault_id: Optional[str]):
    """Start an interactive incident drill. A fault is injected silently for you to diagnose."""
    dojo = DojoManager()
    try:
        drill = dojo.start_drill(fault_id)
        console.print()
        from rich.panel import Panel
        from rich.text import Text

        ticket_text = Text()
        ticket_text.append(f"INCIDENT ESCALATION: {drill['title']}\n", style="bold red")
        ticket_text.append(f"Severity: {drill['severity']}  |  Status: ACTIVE INVESTIGATION\n\n", style="bold yellow")
        ticket_text.append(f"Customer Escalation Report:\n", style="bold white")
        ticket_text.append(f"\"{drill['customer_report']}\"\n\n", style="italic cyan")
        ticket_text.append("Your Mission:\n", style="bold green")
        ticket_text.append("  1. Run 'triageforge diagnose --url http://localhost:80' to inspect stack telemetry.\n")
        ticket_text.append("  2. If stuck, request progressive hints: 'triageforge dojo hint'.\n")
        ticket_text.append("  3. Submit your diagnosis: 'triageforge dojo submit <fault_id>'.\n")

        console.print(Panel(ticket_text, title="[bold red]SRE Incident Training Drill[/bold red]", border_style="red"))
        console.print()
    except Exception as e:
        console.print(f"[bold red]Error starting Dojo drill: {e}[/bold red]")
        sys.exit(1)


@dojo_group.command(name="hint")
def dojo_hint_command():
    """Request a progressive hint for the active incident drill."""
    dojo = DojoManager()
    try:
        hint = dojo.get_hint()
        console.print()
        console.print(f"[bold yellow]Incident Investigation Hint:[/bold yellow]\n  {hint}")
        console.print()
    except Exception as e:
        console.print(f"[bold red]{e}[/bold red]")


@dojo_group.command(name="submit")
@click.argument("fault_id")
def dojo_submit_command(fault_id: str):
    """Submit your root-cause diagnosis for the active drill."""
    dojo = DojoManager()
    try:
        res = dojo.submit_diagnosis(fault_id)
        console.print()
        if res["success"]:
            from rich.panel import Panel
            summary = []
            summary.append(f"[bold green]CORRECT ROOT CAUSE DIAGNOSED![/bold green]\n")
            summary.append(f"Target Fault: [bold cyan]{res['fault_id']}[/bold cyan]")
            summary.append(f"Time to Root Cause: [bold white]{res['elapsed_seconds']}s[/bold white]")
            summary.append(f"Hints Consumed: [bold white]{res['hints_used']}[/bold white]")
            summary.append(f"Performance Score: [bold green]{res['score']} / 100[/bold green]")
            summary.append(f"Rank Awarded: [bold magenta]{res['rank']}[/bold magenta]\n")
            summary.append(f"[dim]{res['remediation']}[/dim]")
            console.print(Panel("\n".join(summary), title="[bold green]Incident Resolved[/bold green]", border_style="green"))
        else:
            console.print(f"[bold red]{res['message']}[/bold red]")
            console.print(f"Attempts recorded: {res['attempts']}")
        console.print()
    except Exception as e:
        console.print(f"[bold red]{e}[/bold red]")


@dojo_group.command(name="stop")
def dojo_stop_command():
    """Cancel the active incident drill and automatically heal the stack."""
    dojo = DojoManager()
    active_id = dojo.stop_drill()
    if active_id:
        console.print(f"[bold cyan]Dojo drill ended. Injected fault '{active_id}' has been healed.[/bold cyan]")
    else:
        console.print("[dim]No active drill was in progress.[/dim]")


# ------------------------------------------------------------------------------
# PCAP & Log Analyzers
# ------------------------------------------------------------------------------

@main.command(name="pcap")
@click.argument("pcap_file", type=click.Path(exists=True))
def pcap_command(pcap_file: str):
    """Analyze a raw packet capture (.pcap) file for TCP retransmissions, resets, and SYN drops."""
    analyzer = PCAPAnalyzer()
    try:
        res = analyzer.analyze_file(pcap_file)
        console.print()
        from rich.table import Table
        t = Table(title=f"PCAP Transport Telemetry: {Path(pcap_file).name}", border_style="dim")
        t.add_column("Metric", style="bold white")
        t.add_column("Value", style="cyan")

        t.add_row("Total Captured Packets", str(res["total_packets"]))
        t.add_row("TCP Packets", str(res["tcp_packets"]))
        t.add_row("TCP SYN Packets", str(res["syn_count"]))
        t.add_row("TCP SYN-ACK Packets", str(res["syn_ack_count"]))
        t.add_row("TCP Resets (RST)", str(res["rst_count"]))
        t.add_row("TCP Retransmissions", str(res["retransmission_count"]))
        t.add_row("Zero-Window Stalls", str(res["zero_window_count"]))
        if res["avg_handshake_rtt_ms"]:
            t.add_row("Avg Handshake RTT", f"{res['avg_handshake_rtt_ms']:.1f}ms")

        console.print(t)
        console.print()
        console.print("[bold yellow]Transport Layer Diagnostic Assessment:[/bold yellow]")
        for f in res["findings"]:
            console.print(f"  * {f}")
        console.print()
    except Exception as e:
        console.print(f"[bold red]Failed to analyze PCAP: {e}[/bold red]")


@main.command(name="logs")
@click.option("--type", "-t", "log_type", type=click.Choice(["vpc-flow", "nginx"]), default="vpc-flow", help="Log format type.")
@click.argument("log_file", type=click.Path(exists=True))
def logs_command(log_type: str, log_file: str):
    """Analyze VPC Flow Logs or web server access logs for rejected traffic or error spikes."""
    analyzer = LogAnalyzer()
    console.print()
    if log_type == "vpc-flow":
        res = analyzer.analyze_vpc_flow_logs(log_file)
        from rich.table import Table
        t = Table(title=f"AWS VPC Flow Log Analysis: {Path(log_file).name}", border_style="dim")
        t.add_column("Metric", style="bold white")
        t.add_column("Value", style="cyan")
        t.add_row("Total Evaluated Flows", str(res["total_flows"]))
        t.add_row("Accepted Traffic Flows", str(res["accepted_flows"]))
        t.add_row("Rejected / Dropped Flows", str(res["rejected_flows"]))
        t.add_row("Reject Rate", f"{res['reject_rate_pct']:.1f}%")
        console.print(t)
        console.print()
        console.print("[bold yellow]Security Group / NACL Findings:[/bold yellow]")
        for f in res["findings"]:
            console.print(f"  * {f}")
    else:
        res = analyzer.analyze_nginx_logs(log_file)
        from rich.table import Table
        t = Table(title=f"Nginx Access Log Error Analysis: {Path(log_file).name}", border_style="dim")
        t.add_column("Metric", style="bold white")
        t.add_column("Value", style="cyan")
        t.add_row("Total HTTP Requests", str(res["total_requests"]))
        t.add_row("2xx Successes", str(res["2xx_success"]))
        t.add_row("4xx Client Errors", str(res["4xx_client_errors"]))
        t.add_row("5xx Server Errors", str(res["5xx_server_errors"]))
        t.add_row("5xx Error Rate", f"{res['error_rate_5xx_pct']:.1f}%")
        console.print(t)
        console.print()
        console.print("[bold yellow]Web Tier Findings:[/bold yellow]")
        for f in res["findings"]:
            console.print(f"  * {f}")
    console.print()


def _find_fault_dir(fault_id: str) -> Optional[Path]:
    base_dir = Path(__file__).resolve().parent.parent / "faults"
    if (base_dir / fault_id).is_dir():
        return base_dir / fault_id
    for p in base_dir.iterdir():
        if p.is_dir() and (fault_id in p.name or p.name.startswith(fault_id)):
            return p
    return None


def _run_script(script_path: Path) -> int:
    """Runs shell script in WSL or native bash."""
    posix_path = str(script_path).replace("\\", "/")
    if os.name == "nt":
        # Check if running under WSL
        cmd = ["wsl", "-d", "Ubuntu", "--", "bash", posix_path]
    else:
        cmd = ["bash", str(script_path)]
    res = subprocess.run(cmd)
    return res.returncode


if __name__ == "__main__":
    main()
