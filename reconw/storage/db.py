import sqlite3
from pathlib import Path

DB_PATH = Path("recon.db")
SCHEMA_PATH = Path(__file__).parent / "schemal.sql"

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_connection(db_path)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.close()
