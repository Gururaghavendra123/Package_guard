"""PackageGuard CLI (Typer): check, scan, serve."""

from __future__ import annotations

import json as _json
import sys

import typer

# Windows consoles default to cp1252 and crash on emoji / box-drawing chars. Force UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

from packageguard.core import engine
from packageguard.output import terminal

app = typer.Typer(
    add_completion=False,
    help="🛡️  PackageGuard — score packages for risk before install; scan projects for malware.",
    no_args_is_help=True,
)


@app.command()
def check(
    package: str = typer.Argument(..., help="Package to score, e.g. 'co1ors' or 'express@4.18.2'."),
    as_json: bool = typer.Option(False, "--json", help="Emit raw JSON instead of the pretty view."),
) -> None:
    """Score a single package for supply-chain risk."""
    try:
        result = engine.check(package)
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if as_json:
        typer.echo(_json.dumps(result, indent=2))
    else:
        terminal.render_check(result)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Project dir or lockfile to scan."),
    as_json: bool = typer.Option(False, "--json", help="Emit raw JSON instead of the pretty view."),
) -> None:
    """Scan a project's dependencies against the known-malware database."""
    try:
        result = engine.scan(path)
    except (FileNotFoundError, ValueError) as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if as_json:
        typer.echo(_json.dumps(result, indent=2))
    else:
        terminal.render_scan(result)


@app.command()
def graph(
    package: str = typer.Argument(..., help="Package to analyse via its dependency graph (GNN)."),
) -> None:
    """Analyse a package's dependency graph with the GraphSAGE GNN (Sem 8). Try 'safe-wrapper'."""
    try:
        r = engine.analyze_graph(package)
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(_json.dumps({k: v for k, v in r.items() if k not in ("nodes", "edges")}, indent=2))
    typer.echo(f"nodes: {len(r['nodes'])}, edges: {len(r['edges'])}")
    if not r["gnn_available"]:
        typer.secho("GNN model not trained — run training/train_gnn.py for graph scoring.",
                    fg=typer.colors.YELLOW)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host."),
    port: int = typer.Option(8000, help="Bind port."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not auto-open the browser."),
) -> None:
    """Launch the HUD dashboard in your browser."""
    import threading
    import webbrowser

    import uvicorn

    url = f"http://{host}:{port}"
    typer.secho(f"🛡️  PackageGuard HUD → {url}", fg=typer.colors.CYAN, bold=True)
    if not no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run("packageguard.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
