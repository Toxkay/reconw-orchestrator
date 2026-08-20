"""ReconW CLI Entrypoint.

Provides commands for executing the reconnaissance pipeline, generating reports,
checking dependencies, and viewing past scan runs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconw.pipeline import build_targets, run_pipeline
from reconw.report.generator import render_html_report
from reconw.storage.db import get_connection, init_db, set_db_path
from reconw.tools.runner import get_tool_version, is_tool_available

console = Console(highlight=False)
cli = typer.Typer(
    name="reconw",
    help="ReconW — Local-First Security Reconnaissance Pipeline Orchestrator",
    add_completion=False,
)


def slugify(text: str) -> str:
    """Converts program name into a clean file slug (e.g. 'Bugcrowd - Tesla' -> 'bugcrowd_tesla')."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower())
    return slug.strip("_") or "reconw"


@cli.command(name="run")
def run_command(
    program_name: str = typer.Option(
        ...,
        "--program",
        "-p",
        help="Target program or organization name (e.g. 'Uber', 'Shopify', 'SnapChat', 'Tiktok')",
    ),
    in_scope: Path = typer.Option(
        ...,
        "--inscope",
        "-i",
        help="Path to in-scope targets text file (e.g. inscope.txt)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    out_of_scope: Path = typer.Option(
        ...,
        "--outscope",
        "-o",
        help="Path to out-of-scope targets text file (e.g. outscope.txt)",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    db_path: Optional[Path] = typer.Option(
        None,
        "--db",
        "-d",
        help="Path to SQLite database file (default: <program_name>.db)",
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        "-r",
        help="Directory to save generated HTML reports",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    no_crawl: bool = typer.Option(
        False,
        "--no-crawl",
        help="Skip the active crawling stage (Katana)",
    ),
    no_report: bool = typer.Option(
        False,
        "--no-report",
        help="Skip generating HTML report",
    ),
) -> None:
    """Execute the full 5-stage reconnaissance pipeline for a specific program."""
    clean_prog = program_name.strip()
    if not clean_prog:
        console.print("[bold red][-] Error:[/bold red] Program name cannot be empty.")
        raise typer.Exit(code=1)

    # 1. Determine database name (defaults to <program_slug>.db)
    if db_path is None:
        target_db = Path(f"{slugify(clean_prog)}.db")
    else:
        target_db = db_path

    set_db_path(target_db)
    init_db(target_db)

    # 2. Validate and load targets
    try:
        targets = build_targets(in_scope, out_of_scope)
    except ValueError as exc:
        console.print(f"[bold red][-] Validation Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if not targets.in_scope:
        console.print("[bold red][-] Error:[/bold red] No valid in-scope targets found.")
        raise typer.Exit(code=1)

    # 3. Print Target Header Banner
    console.print(
        Panel.fit(
            f"[bold cyan]ReconW Orchestrator[/bold cyan]\n"
            f"[bold white]Program Target:[/bold white] [bold yellow]{clean_prog}[/bold yellow]\n"
            f"[green]In-Scope Targets:[/green] {len(targets.in_scope)} domain(s)\n"
            f"[yellow]Out-of-Scope Exclusions:[/yellow] {len(targets.out_of_scope)} rule(s)\n"
            f"[blue]Database Path:[/blue] {target_db.resolve()}",
            title="[bold white]Starting Reconnaissance Run[/bold white]",
            border_style="cyan",
        )
    )

    # 4. Construct CLI args string for audit trail
    args_str = f"reconw run -p \"{clean_prog}\" -i {in_scope} -o {out_of_scope} -d {target_db}"
    if no_crawl:
        args_str += " --no-crawl"

    # 5. Execute Pipeline with Live Stage Output
    try:
        summary = run_pipeline(
            program_name=clean_prog,
            targets=targets,
            cli_args=args_str,
            enable_crawler=not no_crawl,
            generate_report=not no_report,
            reports_dir=reports_dir,
        )

        # 6. Print Execution Results Summary Table
        table = Table(title=f"Run #{summary.run_id} Results Summary — {clean_prog}", border_style="cyan")
        table.add_column("Metric", style="bold white")
        table.add_column("Count", style="bold green", justify="right")

        table.add_row("Program Name", f"[bold yellow]{summary.program_name}[/bold yellow]")
        table.add_row("Discovered Subdomains (Subfinder)", str(summary.subdomains_count))
        table.add_row("Resolved Live Hosts (DNSx)", str(summary.resolved_hosts_count))
        table.add_row("Live HTTP Endpoints (HTTPx)", str(summary.live_endpoints_count))
        table.add_row("Crawled URLs & APIs (Katana)", str(summary.crawled_urls_count))
        table.add_row("Critical Priority Targets", f"[bold red]{summary.critical_count}[/bold red]")
        table.add_row("High Priority Targets", f"[bold yellow]{summary.high_count}[/bold yellow]")
        table.add_row("Execution Duration", f"{summary.duration_seconds}s")

        console.print(table)
        console.print(f"[bold green][+] Run #{summary.run_id} for '{clean_prog}' completed successfully![/bold green]")
        if summary.report_path and summary.report_path.exists():
            console.print(f"[bold cyan][+] HTML Report generated:[/bold cyan] [underline]{summary.report_path.resolve()}[/underline]")
        console.print(f"[blue][+] Database saved:[/blue] {target_db.resolve()}\n")

    except Exception as exc:
        console.print(f"[bold red][!] Pipeline Failed:[/bold red] {exc}")
        raise typer.Exit(code=1)


@cli.command(name="report")
def report_command(
    run_id: int = typer.Option(
        ...,
        "--run-id",
        "-r",
        help="Run ID to generate report for",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Output HTML file path (default: reports/report_run_<id>.html)",
    ),
    db_path: Path = typer.Option(
        Path("reconw.db"),
        "--db",
        "-d",
        help="Path to SQLite database file",
        exists=True,
    ),
) -> None:
    """Generate or regenerate an interactive HTML report from an existing SQLite run."""
    set_db_path(db_path)
    init_db(db_path)

    try:
        report_file = render_html_report(run_id=run_id, output_path=out)
        console.print(f"[bold green][+] Report generated successfully![/bold green]")
        console.print(f"[bold cyan][+] File:[/bold cyan] [underline]{report_file.resolve()}[/underline]\n")
    except Exception as exc:
        console.print(f"[bold red][!] Report generation failed:[/bold red] {exc}")
        raise typer.Exit(code=1)


@cli.command(name="doctor")
def doctor_command() -> None:
    """Check required external binaries and system dependencies."""
    tools = [
        ("subfinder", "Stage 1: Subdomain Discovery"),
        ("dnsx", "Stage 2: DNS Resolution"),
        ("httpx", "Stage 3: HTTP Probing & Screenshots"),
        ("katana", "Stage 4: Active Web Crawling"),
    ]

    table = Table(title="ReconW Dependency Health Check", border_style="cyan")
    table.add_column("Binary", style="bold white")
    table.add_column("Purpose", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Detected Version", style="cyan")

    all_present = True
    for tool_name, purpose in tools:
        if is_tool_available(tool_name):
            version = get_tool_version(tool_name) or "installed"
            table.add_row(tool_name, purpose, "[bold green][READY][/bold green]", version)
        else:
            all_present = False
            table.add_row(tool_name, purpose, "[bold red][MISSING][/bold red]", "Not found in PATH")

    console.print(table)
    if all_present:
        console.print("\n[bold green][+] All required external tools are installed and available in PATH![/bold green]")
    else:
        console.print("\n[bold yellow][!] Note: On Kali Linux, install missing tools via 'sudo apt install -y subfinder httpx-toolkit' or Go.[/bold yellow]")


@cli.command(name="list-runs")
def list_runs_command(
    db_path: Optional[Path] = typer.Option(
        None,
        "--db",
        "-d",
        help="Path to SQLite database file (default: searches local *.db files)",
    ),
) -> None:
    """List historical reconnaissance runs from the SQLite database."""
    if db_path:
        db_files = [db_path]
    else:
        # Search current working directory for *.db files
        db_files = sorted(Path(".").glob("*.db"))
        if not db_files:
            console.print("[yellow]No database files (*.db) found in current directory.[/yellow]")
            return

    for db_file in db_files:
        if not db_file.exists():
            continue

        set_db_path(db_file)
        init_db(db_file)

        conn = get_connection(db_file)
        cursor = conn.execute("SELECT id, program_name, started_at, finished_at, status, cli_args FROM run ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            continue

        table = Table(title=f"Historical Runs ({db_file.name})", border_style="cyan")
        table.add_column("ID", justify="right", style="bold white")
        table.add_column("Program", style="bold yellow")
        table.add_column("Started At", style="dim")
        table.add_column("Finished At", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("CLI Command", style="cyan")

        for r in rows:
            prog = r[1] or "Unknown"
            status_style = "[bold green]COMPLETED[/bold green]" if r[4] == "COMPLETED" else f"[bold yellow]{r[4]}[/bold yellow]"
            table.add_row(str(r[0]), str(prog), str(r[2] or ""), str(r[3] or "In Progress"), status_style, str(r[5] or ""))

        console.print(table)
        console.print()


if __name__ == "__main__":
    cli()
