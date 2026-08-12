from pathlib import Path
# pyrefly: ignore [missing-import]
import typer

from reconw.pipeline import build_targets

# this is how we define our main application
cli = typer.Typer(help="Recon Pipeline Orchestrator")


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

):
    """Recon Pipeline Orchestrator"""
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



# and this is how we run the application
if __name__ == "__main__":
    cli()
