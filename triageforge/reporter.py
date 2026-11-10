"""
TriageForge Report Generator
Renders terminal visualizations via Rich and outputs clean Markdown / JSON artifacts.
"""

from __future__ import annotations
import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from triageforge.models import CheckStatus, DiagnosticReport, Hypothesis


class ReportRenderer:
    """Renders DiagnosticReports to Console, Markdown, and JSON."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_terminal(self, report: DiagnosticReport) -> None:
        """Renders an interactive, beautifully styled terminal summary."""
        self.console.print()
        # Header Banner
        status_color = "green" if report.is_healthy else "red"
        status_badge = (
            "[bold green][HEALTHY] ALL NOMINAL[/bold green]"
            if report.is_healthy
            else "[bold red][ALERT] INCIDENT DETECTED[/bold red]"
        )
        
        header_text = Text()
        header_text.append("TRIAGEFORGE CLOUD DIAGNOSTIC PROBE\n", style="bold cyan")
        header_text.append(f"Target: {report.target_url}  |  Duration: {report.execution_time_ms:.1f}ms  |  Status: ")
        self.console.print(Panel(header_text + Text.from_markup(status_badge), border_style="cyan"))

        # Layer Summary Table
        table = Table(title="Diagnostic Layer Telemetry", header_style="bold magenta", border_style="dim")
        table.add_column("Layer", style="bold white", width=12)
        table.add_column("Status", width=10, justify="center")
        table.add_column("Duration", justify="right", width=10)
        table.add_column("Key Telemetry / Finding", style="dim white")

        status_styles = {
            CheckStatus.OK: "[bold green]PASS[/bold green]",
            CheckStatus.WARN: "[bold yellow]WARN[/bold yellow]",
            CheckStatus.FAIL: "[bold red]FAIL[/bold red]",
            CheckStatus.SKIPPED: "[dim]SKIP[/dim]",
        }

        for layer_name, res in report.layers.items():
            status_str = status_styles.get(res.status, str(res.status))
            # Pick primary message or error
            finding = res.error_message or (res.evidence[0].message if res.evidence else "OK")
            table.add_row(
                layer_name.upper(),
                status_str,
                f"{res.duration_ms:.1f}ms",
                finding,
            )

        self.console.print(table)
        self.console.print()

        # Hypotheses Section
        if report.is_healthy:
            self.console.print(
                Panel(
                    "[bold green]No faults detected.[/bold green] All layers operating within nominal SLA thresholds.",
                    title="[bold green]System Health[/bold green]",
                    border_style="green",
                )
            )
        else:
            self.console.print("[bold yellow]Ranked Root Cause Hypotheses:[/bold yellow]")
            for idx, hyp in enumerate(report.hypotheses, start=1):
                self._render_hypothesis_panel(hyp, idx)

        self.console.print()

    def _render_hypothesis_panel(self, hyp: Hypothesis, rank: int) -> None:
        confidence_pct = int(hyp.confidence * 100)
        border_col = "red" if rank == 1 else "yellow"

        content = []
        content.append(f"[bold white]Fault Category:[/bold white] {hyp.category}  |  [bold white]Severity:[/bold white] [{border_col}]{hyp.severity}[/{border_col}]  |  [bold white]Confidence:[/bold white] [bold {border_col}]{confidence_pct}%[/bold {border_col}]")
        content.append(f"\n[bold white]Root Cause Analysis:[/bold white]\n{hyp.root_cause}\n")

        content.append("[bold white]Supporting Evidence:[/bold white]")
        for ev in hyp.supporting_evidence:
            content.append(f"  * {ev}")

        content.append(f"\n[bold green]Next Best Diagnostic Command (SRE Runbook):[/bold green]")
        content.append(f"  [bold yellow]{hyp.next_best_command}[/bold yellow]\n")

        content.append(f"[bold cyan]Recommended Remediation:[/bold cyan]\n  {hyp.remediation_summary}")

        panel = Panel(
            "\n".join(content),
            title=f"[bold {border_col}]#{rank} {hyp.title} ({confidence_pct}% Match)[/bold {border_col}]",
            border_style=border_col,
            expand=True,
        )
        self.console.print(panel)

    def to_markdown(self, report: DiagnosticReport) -> str:
        """Converts report into enterprise support case / post-mortem markdown format."""
        lines = []
        lines.append(f"# TriageForge Diagnostic Report: `{report.target_url}`")
        lines.append(f"**Timestamp**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"**Execution Latency**: {report.execution_time_ms:.1f}ms  ")
        lines.append(f"**Overall Assessment**: {'HEALTHY' if report.is_healthy else 'INCIDENT ACTIVE'}  \n")

        lines.append("## Executive Summary")
        lines.append(f"{report.executive_summary}\n")

        lines.append("## Diagnostic Layer Breakdown")
        lines.append("| Layer | Status | Duration | Observation |")
        lines.append("|:------|:------:|:--------:|:------------|")

        for name, layer in report.layers.items():
            obs = layer.error_message or (layer.evidence[0].message if layer.evidence else "OK")
            # Sanitize pipe characters
            obs = obs.replace("|", "/")
            lines.append(f"| **{name.upper()}** | `{layer.status.value}` | {layer.duration_ms:.1f}ms | {obs} |")

        lines.append("\n## Ranked Failure Hypotheses")
        if report.is_healthy:
            lines.append("No active faults detected. All systems nominal.")
        else:
            for idx, hyp in enumerate(report.hypotheses, start=1):
                conf_pct = int(hyp.confidence * 100)
                lines.append(f"### #{idx}. {hyp.title} (`{conf_pct}% Confidence`)")
                lines.append(f"- **Fault Identifier**: `{hyp.fault_type}`")
                lines.append(f"- **Category / Severity**: {hyp.category} | `{hyp.severity}`")
                lines.append(f"- **Root Cause**: {hyp.root_cause}")
                lines.append("- **Observed Evidence**:")
                for ev in hyp.supporting_evidence:
                    lines.append(f"  - {ev}")
                lines.append(f"\n```bash\n# Next best verification command\n{hyp.next_best_command}\n```")
                lines.append(f"- **Remediation**: {hyp.remediation_summary}\n")

        return "\n".join(lines)

    def to_json(self, report: DiagnosticReport, indent: int = 2) -> str:
        """Serializes the report into formatted JSON."""
        return report.model_dump_json(indent=indent)
