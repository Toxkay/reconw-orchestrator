from pathlib import Path
# pyrefly: ignore [missing-import]
import typer

from reconw.pipeline import build_targets
from reconw.storage.db import init_db

cli = typer.Typer(help="ReconW Pipeline Orchestrator")


@cli.command()
def reconw(
    in_scope: Path = typer.Option(
        ...,
        "--inscope",
        "-i",
        help="Path to in-scope targets text file",
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
        help="Path to out-of-scope targets text file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    db_path: Path = typer.Option(
        Path("reconw.db"),
        "--db",
        "-d",
        help="Path to ReconW database file",
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
):
    """ReconW Pipeline Orchestrator"""
    # 1. Automatically initialize database tables
    init_db(db_path)
    typer.secho(f"[*] Database ready at: {db_path}", fg=typer.colors.CYAN)

    # 2. Validate and load scope
    try:
        targets = build_targets(in_scope, out_of_scope)
    except ValueError as exc:
        typer.secho(f"[-] Validation error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    for target in targets.in_scope:
        typer.echo(f"[+] Validated in-scope target: {target}")

    for target in targets.out_of_scope:
        typer.echo(f"[-] Validated out-of-scope target: {target}")

    typer.echo(f"[+] Loaded {len(targets.in_scope)} in-scope target(s) from: {in_scope}")
    typer.echo(f"[-] Loaded {len(targets.out_of_scope)} out-of-scope target(s) from: {out_of_scope}")


if __name__ == "__main__":
    cli()
