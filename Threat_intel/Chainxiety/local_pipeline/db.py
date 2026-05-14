import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DATA_DIR, DB_PATH


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)


@contextmanager
def connect():
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dedupe_key TEXT UNIQUE NOT NULL,
                source_chat_id TEXT,
                source_message_id TEXT,
                package_name TEXT,
                version TEXT,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                report_path TEXT,
                summary_path TEXT
            )
            """
        )
        conn.commit()


def enqueue_job(dedupe_key, payload, package_name, version, source_chat_id, source_message_id):
    with connect() as conn:
        try:
            conn.execute(
                """
                INSERT INTO jobs
                (dedupe_key, source_chat_id, source_message_id, package_name, version, payload_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)
                """,
                (
                    dedupe_key,
                    str(source_chat_id or ""),
                    str(source_message_id or ""),
                    package_name,
                    version,
                    json.dumps(payload),
                    now_iso(),
                ),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def claim_next_job():
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE status = 'queued' ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if not row:
            return None

        conn.execute(
            "UPDATE jobs SET status = 'processing', started_at = ? WHERE id = ?",
            (now_iso(), row["id"]),
        )
        conn.commit()
        return dict(row)


def complete_job(job_id, report_path, summary_path):
    with connect() as conn:
        conn.execute(
            "UPDATE jobs SET status = 'done', finished_at = ?, report_path = ?, summary_path = ? WHERE id = ?",
            (now_iso(), report_path, summary_path, job_id),
        )
        conn.commit()


def fail_job(job_id, error):
    with connect() as conn:
        conn.execute(
            "UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?",
            (now_iso(), error[:2000], job_id),
        )
        conn.commit()
