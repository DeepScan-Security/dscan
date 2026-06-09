"""Report formatting for dscan attack.

:class:`AttackReporter` wraps an :class:`~dscan.attack.models.AttackReport`
and renders it: grouped/filtered data access, JSON serialisation (and
file output), and rich console output (summary panel, findings table,
recommendations). Formatting only — no runner, network, or CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import AttackFinding, AttackReport, Severity

__all__ = ["AttackReporter"]


class AttackReporter:
    SEVERITY_COLORS = {
        "critical": "red",
        "high": "dark_orange",
        "medium": "yellow",
        "low": "dim",
    }

    def __init__(self, report: AttackReport, console: Optional[Console] = None) -> None:
        self.report = report
        self.console = console or Console()

    # ── Data access ───────────────────────────────────────────────────
    def findings_by_severity(self) -> dict[str, list]:
        result: dict[str, list] = {s.value: [] for s in Severity}
        for f in self.report.findings:
            result[f.payload.severity.value].append(f)
        return result

    def findings_by_category(self) -> dict[str, list]:
        result: dict[str, list] = {}
        for f in self.report.findings:
            result.setdefault(f.payload.category.value, []).append(f)
        return result

    def succeeded_findings(self) -> list[AttackFinding]:
        return [f for f in self.report.findings if f.succeeded]

    # ── Serialisation ─────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "target": self.report.target,
            "summary": {
                "total_payloads": self.report.total_payloads,
                "critical_count": self.report.critical_count,
                "high_count": self.report.high_count,
                "passed": self.report.passed,
                "duration_seconds": self.report.duration_seconds,
                "timestamp": self.report.timestamp,
                "succeeded_count": len(self.succeeded_findings()),
            },
            "context": {
                "framework": self.report.context.framework,
                "tools": self.report.context.tool_names,
                "goal": self.report.context.goal,
            },
            "findings": [self._finding_to_dict(f) for f in self.report.findings],
        }

    def _finding_to_dict(self, f: AttackFinding) -> dict:
        return {
            "id": f.payload.id,
            "category": f.payload.category.value,
            "name": f.payload.name,
            "severity": f.payload.severity.value,
            "succeeded": f.succeeded,
            "confidence": round(f.confidence, 2),
            "evidence": f.evidence,
            "recommendation": f.recommendation,
            "tool_calls_made": f.tool_calls_made,
            "baseline_calls": f.baseline_tool_calls,
            "detection_method": f.detection_method,
            "agent_response": f.agent_response,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    # ── Rich console output ───────────────────────────────────────────
    def print_summary(self) -> None:
        passed = self.report.passed
        status_color = "green" if passed else "red"
        status_text = "✓ PASSED" if passed else "✗ FAILED"
        crit = self.report.critical_count
        high = self.report.high_count

        lines = [
            f"[bold {status_color}]{status_text}[/]  "
            f"[red]{crit} critical[/]  [dark_orange]{high} high[/]",
            f"[dim]{self.report.total_payloads} payloads  •  "
            f"{self.report.duration_seconds}s  •  {self.report.target}[/]",
        ]
        self.console.print(
            Panel("\n".join(lines), title="[bold]dscan attack[/]", border_style=status_color)
        )

    def print_findings(self, succeeded_only: bool = False) -> None:
        findings = self.report.findings
        if succeeded_only:
            findings = [f for f in findings if f.succeeded]
        if not findings:
            self.console.print("[green]✓ No findings to display[/]")
            return

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings = sorted(
            findings,
            key=lambda f: (sev_order.get(f.payload.severity.value, 99), not f.succeeded),
        )

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("ID", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Category", width=22)
        table.add_column("Name", width=28)
        table.add_column("Result", width=10)
        table.add_column("Confidence", width=12)
        table.add_column("Method", width=12)

        for f in findings:
            sev = f.payload.severity.value
            color = self.SEVERITY_COLORS.get(sev, "")
            result_text = "[red]✗ Found[/]" if f.succeeded else "[green]✓ Clean[/]"
            table.add_row(
                f.payload.id,
                f"[{color}]{sev.upper()}[/]",
                f.payload.category.value,
                f.payload.name,
                result_text,
                f"{f.confidence:.0%}",
                f.detection_method,
            )
        self.console.print(table)

    def print_recommendations(self) -> None:
        succeeded = self.succeeded_findings()
        if not succeeded:
            self.console.print(
                "[green]✓ No vulnerabilities found — no recommendations needed[/]"
            )
            return

        self.console.print("\n[bold]Recommendations[/]")
        for f in succeeded:
            color = self.SEVERITY_COLORS.get(f.payload.severity.value, "")
            self.console.print(f"\n[{color}][bold]{f.payload.id}[/bold] {f.payload.name}[/]")
            self.console.print(f"  [dim]{f.evidence}[/dim]")
            if f.recommendation:
                self.console.print(f"  [white]{f.recommendation}[/white]")

    def print_full_report(self) -> None:
        self.print_summary()
        self.console.print()
        self.print_findings()
        self.console.print()
        self.print_recommendations()
