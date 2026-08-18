from pathlib import Path
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field, field_validator


class ScopeFilesConfig(BaseModel):
    """Validates the input files provided by the user."""
    in_scope_file: Path
    out_of_scope_file: Path | None = None

    @field_validator("in_scope_file")
    @classmethod
    def validate_in_scope_file(cls, path: Path) -> Path:
        if not path.exists():
            raise ValueError(f"In-scope file does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"In-scope path is not a file: {path}")
        if path.stat().st_size == 0:
            raise ValueError(f"In-scope file is empty: {path}")
        return path

    @field_validator("out_of_scope_file")
    @classmethod
    def validate_out_of_scope_file(cls, path: Path | None) -> Path | None:
        if path is not None and not path.exists():
            raise ValueError(f"Out-of-scope file does not exist: {path}")
        return path
