import sqlite3
from pathlib import Path

DB_PATH = Path("reconw.db")
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def set_db_path(db_path: Path) -> None:
    """Sets the global default database path for the current process."""
    global DB_PATH
    DB_PATH = Path(db_path)


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    target_path = db_path if db_path is not None else DB_PATH
    conn = sqlite3.connect(target_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path | None = None) -> None:
    conn = get_connection(db_path)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.close()
