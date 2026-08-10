from pathlib import Path
from typing import Optional
# pyrefly: ignore [missing-import]
import typer

# this is how we define our main application
cli = typer.Typer(help="Recon Pipeline Orchestrator")


def load_targets(file_path: Path) -> list[str]:
    """Read targets from file, filtering out comments and blank lines."""
    return [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


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
    out_of_scope: Optional[Path] = typer.Option(
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
    in_targets = load_targets(in_scope)
    out_targets = load_targets(out_of_scope) if out_of_scope else []

    typer.echo(f"[+] Loaded {len(in_targets)} in-scope target(s) from: {in_scope}")


    if out_of_scope:
        typer.echo(f"[-] Loaded {len(out_targets)} out-of-scope target(s) from: {out_of_scope}")

    else:
        typer.echo("[-] No out-of-scope targets specified.")



# and this is how we run the application
if __name__ == "__main__":
    cli()
