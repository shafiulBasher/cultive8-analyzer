from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from .config import DATA_DIR, DB_PATH


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


@contextmanager
def db_session():
    con = connect()
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db() -> None:
    with db_session() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            status TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'queued',
            processed_chunks INTEGER NOT NULL DEFAULT 0,
            findings_count INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            report_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            chunk_index INTEGER NOT NULL,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            status TEXT NOT NULL,
            prompt_tokens INTEGER,
            model_ms INTEGER,
            error TEXT,
            response_json TEXT,
            UNIQUE(job_id, chunk_index)
        );
        CREATE TABLE IF NOT EXISTS findings (
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            finding_key TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            PRIMARY KEY(job_id, finding_key)
        );
        """)


def create_job(job_id: str, filename: str, file_path: str) -> None:
    ts = now_iso()
    with db_session() as con:
        con.execute("INSERT INTO jobs(id,filename,file_path,status,phase,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (job_id, filename, file_path, "queued", "queued", ts, ts))


def update_job(job_id: str, **fields: Any) -> None:
    allowed = {"status", "phase", "processed_chunks", "findings_count", "error", "report_json"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = now_iso()
    if "report_json" in updates and not isinstance(updates["report_json"], str):
        updates["report_json"] = json.dumps(updates["report_json"], ensure_ascii=False)
    assignments = ",".join(f"{key}=?" for key in updates)
    with db_session() as con:
        con.execute(f"UPDATE jobs SET {assignments} WHERE id=?", (*updates.values(), job_id))


def save_chunk(job_id: str, chunk_index: int, start_line: int, end_line: int,
               status: str, prompt_tokens: int | None = None, model_ms: int | None = None,
               error: str | None = None, response: Any = None) -> None:
    with db_session() as con:
        con.execute("""INSERT OR REPLACE INTO chunks
            (job_id,chunk_index,start_line,end_line,status,prompt_tokens,model_ms,error,response_json)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (job_id, chunk_index, start_line, end_line, status, prompt_tokens, model_ms,
             error, json.dumps(response, ensure_ascii=False) if response is not None else None))


def save_findings(job_id: str, findings: list[dict[str, Any]]) -> None:
    with db_session() as con:
        for item in findings:
            key = item.get("_key") or f"{item.get('attack_type')}|{item.get('ip_or_identifier')}|{item.get('target','')}"
            payload = {k: v for k, v in item.items() if k != "_key"}
            con.execute("INSERT OR REPLACE INTO findings(job_id,finding_key,finding_json) VALUES(?,?,?)",
                        (job_id, key, json.dumps(payload, ensure_ascii=False)))
        con.execute("UPDATE jobs SET findings_count=(SELECT COUNT(*) FROM findings WHERE job_id=?), updated_at=? WHERE id=?",
                    (job_id, now_iso(), job_id))


def get_job(job_id: str) -> dict[str, Any] | None:
    with db_session() as con:
        row = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json")) if result.get("report_json") else None
        return result


def get_findings(job_id: str) -> list[dict[str, Any]]:
    with db_session() as con:
        rows = con.execute("SELECT finding_json FROM findings WHERE job_id=?", (job_id,)).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_chunks(job_id: str) -> list[dict[str, Any]]:
    with db_session() as con:
        rows = con.execute("SELECT chunk_index,start_line,end_line,status,prompt_tokens,model_ms,error FROM chunks WHERE job_id=? ORDER BY chunk_index", (job_id,)).fetchall()
    return [dict(r) for r in rows]
