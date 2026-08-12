from pathlib import Path

def load_targets(file_path: Path) -> list[str]:
    """Read targets from file, filtering out comments and blank lines."""
    return [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]