"""SQLite 存储层：表结构定义、数据写入与查询接口。"""

import sqlite3
import os
from typing import Iterable, List, Dict, Any, Optional, Tuple
from contextlib import contextmanager


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT DEFAULT '',
    status TEXT DEFAULT '',
    source_file TEXT DEFAULT '',
    raw TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_subject ON logs(subject);
CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action);
CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status);
CREATE INDEX IF NOT EXISTS idx_logs_subject_ts ON logs(subject, ts);
CREATE INDEX IF NOT EXISTS idx_logs_action_ts ON logs(action, ts);
"""


class Storage:
    """SQLite 存储封装。"""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        is_new = (db_path == ":memory:") or (not os.path.exists(db_path))
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA cache_size=-65536;")
        if is_new:
            self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(SCHEMA_SQL)

    @contextmanager
    def transaction(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def insert_many(self, rows: Iterable[Dict[str, Any]]) -> int:
        """批量写入日志记录，返回写入数量。"""
        sql = (
            "INSERT INTO logs (ts, subject, action, resource, status, source_file, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        tuples = [
            (
                r["ts"],
                r["subject"],
                r["action"],
                r.get("resource", ""),
                r.get("status", ""),
                r.get("source_file", ""),
                r.get("raw", ""),
            )
            for r in rows
        ]
        if not tuples:
            return 0
        with self.transaction() as conn:
            conn.executemany(sql, tuples)
        return len(tuples)

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM logs")
        return cur.fetchone()[0]

    def time_range(self) -> Optional[Tuple[float, float]]:
        cur = self._conn.execute("SELECT MIN(ts), MAX(ts) FROM logs")
        row = cur.fetchone()
        if row[0] is None:
            return None
        return (row[0], row[1])

    def iter_all(self):
        cur = self._conn.execute(
            "SELECT ts, subject, action, resource, status, source_file FROM logs ORDER BY ts"
        )
        for r in cur:
            yield dict(r)

    def group_by_subject(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT subject,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   COUNT(DISTINCT action) AS action_types,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM logs
            GROUP BY subject
            ORDER BY cnt DESC
        """
        return [dict(r) for r in self._conn.execute(sql)]

    def group_by_action(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT action,
                   COUNT(*) AS cnt,
                   COUNT(DISTINCT subject) AS subject_cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM logs
            GROUP BY action
            ORDER BY cnt DESC
        """
        return [dict(r) for r in self._conn.execute(sql)]

    def group_by_status(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT status, COUNT(*) AS cnt
            FROM logs
            GROUP BY status
            ORDER BY cnt DESC
        """
        return [dict(r) for r in self._conn.execute(sql)]

    def group_by_time_window(self, window_seconds: int) -> List[Dict[str, Any]]:
        sql = f"""
            SELECT CAST(ts / {window_seconds} AS INTEGER) AS bucket,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   COUNT(DISTINCT subject) AS subject_cnt,
                   COUNT(DISTINCT action) AS action_cnt,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM logs
            GROUP BY bucket
            ORDER BY bucket
        """
        return [dict(r) for r in self._conn.execute(sql)]

    def group_by_subject_action(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT subject, action, COUNT(*) AS cnt, MIN(ts) AS t_min, MAX(ts) AS t_max
            FROM logs
            GROUP BY subject, action
            ORDER BY cnt DESC
        """
        return [dict(r) for r in self._conn.execute(sql)]

    def subject_action_time_series(self, window_seconds: int) -> List[Dict[str, Any]]:
        sql = f"""
            SELECT CAST(ts / {window_seconds} AS INTEGER) AS bucket,
                   subject,
                   action,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min
            FROM logs
            GROUP BY bucket, subject, action
            ORDER BY bucket, cnt DESC
        """
        return [dict(r) for r in self._conn.execute(sql)]

    def query(self, sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._conn.execute(sql, params)]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
