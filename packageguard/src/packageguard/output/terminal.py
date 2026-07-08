"""Rich terminal rendering for `check` and `scan` results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

LEVEL_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold green",
}
SIGNAL_ICON = {"critical": ("🔴", "red"), "warn": ("🟡", "yellow"), "ok": ("🟢", "green")}
SEVERITY_STYLE = {"critical": "bold white on red", "high": "bold red",
                  "medium": "bold yellow", "low": "cyan"}


def _bar(contribution: float, width: int = 24) -> Text:
    """Diverging bar around a center axis: red to the right (risk), green to the left (safe)."""
    half = width // 2
    mag = max(-1.0, min(1.0, contribution / 3.0))
    cells = round(abs(mag) * half)
    if contribution >= 0:
        return Text(" " * half + "│" + "█" * cells + " " * (half - cells), style="red")
    return Text(" " * (half - cells) + "█" * cells + "│" + " " * half, style="green")


def render_check(result: dict) -> None:
    level = result["level"]
    score = result["score"]
    header = Text.assemble(
        (f" {result['verdict']} ", LEVEL_STYLE.get(level, "bold")),
        ("  ", ""),
        (f"{result['name']}@{result['version']}", "bold cyan"),
        ("   score ", "dim"),
        (f"{score:.2f}", LEVEL_STYLE.get(level, "bold")),
        (f"   [{result['source']}]", "dim"),
    )

    table = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    table.add_column("Signal", style="white", no_wrap=True)
    table.add_column("Attribution", no_wrap=True)
    table.add_column("Detail", style="dim")
    for f in result["features"]:
        table.add_row(f["label"], _bar(f["contribution"]),
                      f'{f["detail"]}  ({f["contribution"]:+.2f})')

    console.print(Panel(table, title="🛡️  PackageGuard · check", subtitle=header,
                        border_style=SEVERITY_STYLE.get(level, "cyan")))
    if result.get("note"):
        console.print(f"[dim]{result['note']}[/dim]")


def render_scan(result: dict) -> None:
    s = result["summary"]
    head = (f"[bold]{result['issue_count']}[/bold] issue(s) in "
            f"[bold]{result['total_dependencies']}[/bold] dependencies  "
            f"[red]{s['critical']} critical[/red] · [yellow]{s['high']} high[/yellow]")
    console.print(Panel(head, title="🦠  PackageGuard · scan", border_style="cyan"))

    if not result["issues"]:
        console.print("[green]✓ No known-malicious dependencies found.[/green]")
        return

    for issue in result["issues"]:
        body = Text()
        body.append(f"{issue['reason']}\n", style="white")
        body.append(f"Path: {issue['path']}\n", style="dim")
        if issue.get("replacement"):
            body.append(f"Suggested replacement: {issue['replacement']}\n", style="cyan")
        body.append("\nRemediation:\n", style="bold")
        for i, step in enumerate(issue["remediation"], 1):
            body.append(f"  {i}. {step}\n", style="green")
        title = f"{issue['severity'].upper()}: {issue['name']}@{issue['version']}"
        console.print(Panel(body, title=title,
                            border_style=SEVERITY_STYLE.get(issue["severity"], "red")))
