from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_DB_PATH = Path(".runtime/styrecon.sqlite")


def _utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  project TEXT NOT NULL,
  target TEXT NOT NULL,
  profile TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at_utc TEXT NOT NULL,
  finished_at_utc TEXT,
  cli_command TEXT NOT NULL,
  config_json TEXT NOT NULL,
  scope_allow_path TEXT,
  scope_block_path TEXT,
  tool_versions_json TEXT,
  warnings_count INTEGER NOT NULL DEFAULT 0,
  errors_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS runs_project_target_time ON runs(project, target, started_at_utc);
CREATE INDEX IF NOT EXISTS runs_target_time ON runs(target, started_at_utc);

CREATE TABLE IF NOT EXISTS assets (
  asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  host TEXT,
  created_at_utc TEXT NOT NULL,
  UNIQUE(project, kind, value)
);
CREATE INDEX IF NOT EXISTS assets_project_kind ON assets(project, kind);
CREATE INDEX IF NOT EXISTS assets_host ON assets(host);

CREATE TABLE IF NOT EXISTS observations (
  obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  asset_id INTEGER NOT NULL,
  tool TEXT NOT NULL,
  data_json TEXT NOT NULL,
  data_hash TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  UNIQUE(run_id, asset_id, tool),
  FOREIGN KEY(run_id) REFERENCES runs(run_id),
  FOREIGN KEY(asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS obs_run_tool ON observations(run_id, tool);
CREATE INDEX IF NOT EXISTS obs_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS obs_run ON observations(run_id);
"""


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    # Reduce "database is locked" issues on multi-connection workloads.
    # busy_timeout is per-connection, so set it on every connect.
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    # WAL is a good default for local, append-heavy workloads (runs/observations).
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")


def ensure_db_initialized(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        _apply_pragmas(conn)
        conn.executescript(SCHEMA_SQL)
        conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", ("schema_version", "1"))
        conn.commit()
    finally:
        conn.close()


@dataclass
class Db:
    db_path: Path
    conn: sqlite3.Connection | None = None

    def __enter__(self) -> "Db":
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        _apply_pragmas(self.conn)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        if not self.conn:
            return
        try:
            if exc is None:
                self.conn.commit()
            else:
                self.conn.rollback()
        finally:
            self.conn.close()
            self.conn = None

    @contextmanager
    def tx(self):
        assert self.conn is not None
        try:
            yield
            self.conn.commit()
        except Exception:  # noqa: BLE001
            self.conn.rollback()
            raise

    def insert_run(
        self,
        run_id: str,
        project: str,
        target: str,
        profile: str,
        status: str,
        cli_command: str,
        config_json: str,
        scope_allow_path: Optional[str],
        scope_block_path: Optional[str],
    ) -> None:
        assert self.conn is not None
        self.conn.execute(
            """
            INSERT INTO runs(run_id,project,target,profile,status,started_at_utc,cli_command,config_json,scope_allow_path,scope_block_path)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (run_id, project, target, profile, status, _utc_iso(), cli_command, config_json, scope_allow_path, scope_block_path),
        )

    def update_run_status(self, run_id: str, status: str, warnings_count: int, errors_count: int) -> None:
        assert self.conn is not None
        self.conn.execute(
            """
            UPDATE runs
            SET status=?, finished_at_utc=?, warnings_count=?, errors_count=?
            WHERE run_id=?
            """,
            (status, _utc_iso(), warnings_count, errors_count, run_id),
        )

    def get_run_status(self, run_id: str) -> Optional[str]:
        assert self.conn is not None
        row = self.conn.execute("SELECT status FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return str(row["status"]) if row else None

    def get_or_create_asset(self, project: str, kind: str, value: str, host: Optional[str]) -> int:
        assert self.conn is not None
        row = self.conn.execute(
            "SELECT asset_id FROM assets WHERE project=? AND kind=? AND value=?",
            (project, kind, value),
        ).fetchone()
        if row:
            return int(row["asset_id"])
        cur = self.conn.execute(
            "INSERT INTO assets(project,kind,value,host,created_at_utc) VALUES(?,?,?,?,?)",
            (project, kind, value, host, _utc_iso()),
        )
        return int(cur.lastrowid)

    def upsert_observation(self, run_id: str, asset_id: int, tool: str, data_json: str, data_hash: str) -> None:
        assert self.conn is not None
        self.conn.execute(
            """
            INSERT INTO observations(run_id,asset_id,tool,data_json,data_hash,created_at_utc)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(run_id,asset_id,tool) DO UPDATE SET
              data_json=excluded.data_json,
              data_hash=excluded.data_hash,
              created_at_utc=excluded.created_at_utc
            """,
            (run_id, asset_id, tool, data_json, data_hash, _utc_iso()),
        )

    def list_runs(self, project: str, target: str, profile: Optional[str]) -> List[Dict[str, Any]]:
        assert self.conn is not None
        if profile:
            rows = self.conn.execute(
                """
                SELECT * FROM runs
                WHERE project=? AND target=? AND profile=?
                ORDER BY started_at_utc DESC
                """,
                (project, target, profile),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT * FROM runs
                WHERE project=? AND target=?
                ORDER BY started_at_utc DESC
                """,
                (project, target),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_run_by_id(self, run_id: str) -> Optional[Dict[str, Any]]:
        assert self.conn is not None
        row = self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def get_hosts_for_run(self, run_id: str, project: str, tools: Optional[Iterable[str]] = None) -> List[str]:
        assert self.conn is not None
        if tools:
            tools_list = list(tools)
            placeholders = ",".join(["?"] * len(tools_list))
            args: List[Any] = [run_id, project] + tools_list
            q = f"""
                SELECT a.value AS host
                FROM observations o
                JOIN assets a ON a.asset_id=o.asset_id
                WHERE o.run_id=? AND a.project=? AND a.kind='host'
                  AND o.tool IN ({placeholders})
            """
            rows = self.conn.execute(q, args).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT a.value AS host
                FROM observations o
                JOIN assets a ON a.asset_id=o.asset_id
                WHERE o.run_id=? AND a.project=? AND a.kind='host'
                """,
                (run_id, project),
            ).fetchall()
        return sorted({str(r["host"]) for r in rows})

    def get_httpx_for_run(self, run_id: str, project: str) -> List[Tuple[str, str, str]]:
        """
        Returns list of (url, data_json, data_hash) for tool=httpx.
        """
        assert self.conn is not None
        rows = self.conn.execute(
            """
            SELECT a.value AS url, o.data_json AS data_json, o.data_hash AS data_hash
            FROM observations o
            JOIN assets a ON a.asset_id=o.asset_id
            WHERE o.run_id=? AND a.project=? AND a.kind='url' AND o.tool='httpx'
            """,
            (run_id, project),
        ).fetchall()
        return [(str(r["url"]), str(r["data_json"]), str(r["data_hash"])) for r in rows]
