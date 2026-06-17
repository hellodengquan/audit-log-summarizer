"""SQLite 存储层：按月分表 + TTL 清理 + 多维聚合查询接口。

设计：
- 每个月份一张 logs_YYYYMM 表，结构与原 logs 表一致
- UNION ALL 视图 logs_all 提供透明跨月查询
- TTL 清理：按月表粒度删除过期数据
- 所有查询方法默认走 logs_all 视图
"""

import sqlite3
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, List, Dict, Any, Optional, Tuple
from contextlib import contextmanager


_LOG_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS {table} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT DEFAULT '',
    status TEXT DEFAULT '',
    source_file TEXT DEFAULT '',
    raw TEXT DEFAULT ''
);
"""

_INDEX_TEMPLATES = [
    "CREATE INDEX IF NOT EXISTS idx_{table}_ts ON {table}(ts);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_subject ON {table}(subject);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_action ON {table}(action);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_status ON {table}(status);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_subject_ts ON {table}(subject, ts);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_action_ts ON {table}(action, ts);",
]

_ALL_VIEW_TEMPLATE = "CREATE VIEW IF NOT EXISTS logs_all AS {union};"

_META_TABLE = """
CREATE TABLE IF NOT EXISTS _meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _month_table_name(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, timezone.utc)
    return f"logs_{dt.strftime('%Y%m')}"


def _known_month_tables(conn: sqlite3.Connection) -> List[str]:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_2%' ORDER BY name"
    )
    return [row[0] for row in cur if re.match(r'^logs_2\d{5,6}$', row[0])]


def _ensure_table(conn: sqlite3.Connection, table: str) -> None:
    conn.execute(_LOG_TABLE_SCHEMA.format(table=table))
    for idx_sql in _INDEX_TEMPLATES:
        conn.execute(idx_sql.format(table=table))


def _rebuild_all_view(conn: sqlite3.Connection) -> None:
    tables = _known_month_tables(conn)
    conn.execute("DROP VIEW IF EXISTS logs_all;")
    if not tables:
        return
    union = " UNION ALL ".join(f"SELECT * FROM {t}" for t in tables)
    conn.execute(_ALL_VIEW_TEMPLATE.format(union=union))


class Storage:
    """SQLite 存储封装（按月分表 + TTL 清理）。"""

    def __init__(self, db_path: str = ":memory:", ttl_days: Optional[int] = None):
        self.db_path = db_path
        self.ttl_days = ttl_days
        is_new = (db_path == ":memory:") or (not os.path.exists(db_path))
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA cache_size=-65536;")
        self._table_cache: set = set()
        if is_new:
            self._init_meta()
            self._rebuild_view()

    def _init_meta(self) -> None:
        with self._conn:
            self._conn.execute(_META_TABLE)
            if self.ttl_days is not None:
                self._conn.execute(
                    "INSERT OR REPLACE INTO _meta (key, value) VALUES ('ttl_days', ?)",
                    (str(self.ttl_days),)
                )

    def _rebuild_view(self) -> None:
        with self._conn:
            _rebuild_all_view(self._conn)

    def _ensure_month_table(self, ts: float) -> str:
        table = _month_table_name(ts)
        if table not in self._table_cache:
            with self._conn:
                _ensure_table(self._conn, table)
            self._table_cache.add(table)
        return table

    @contextmanager
    def transaction(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def insert_many(self, rows: Iterable[Dict[str, Any]]) -> int:
        """批量写入日志记录（自动按月份分表），返回写入数量。"""
        sql_template = (
            "INSERT INTO {table} (ts, subject, action, resource, status, source_file, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        by_table: Dict[str, List[Tuple]] = defaultdict(list)
        for r in rows:
            ts = r["ts"]
            table = _month_table_name(ts)
            by_table[table].append((
                ts,
                r["subject"],
                r["action"],
                r.get("resource", ""),
                r.get("status", ""),
                r.get("source_file", ""),
                r.get("raw", ""),
            ))

        total = 0
        new_tables = []
        with self.transaction() as conn:
            for table, tuples in by_table.items():
                if table not in self._table_cache:
                    _ensure_table(conn, table)
                    self._table_cache.add(table)
                    new_tables.append(table)
                conn.executemany(sql_template.format(table=table), tuples)
                total += len(tuples)

        if new_tables:
            self._rebuild_view()
        return total

    # ---- TTL 清理 ----
    def purge_expired(self, ttl_days: Optional[int] = None) -> int:
        """删除超过 ttl_days 天的月表，返回被删除的行数。

        策略：按月表粒度整表删除（而非逐行），因为审计日志通常按月归档。
        如果某月表中有部分数据仍在 TTL 内，则保留整张表不删。
        """
        days = ttl_days or self.ttl_days
        if days is None:
            return 0

        cutoff_ts = time.time() - days * 86400
        cutoff_dt = datetime.fromtimestamp(cutoff_ts, timezone.utc)
        cutoff_month = cutoff_dt.strftime("%Y%m")

        tables = _known_month_tables(self._conn)
        deleted_rows = 0
        tables_dropped = []
        for table in tables:
            month_str = table.replace("logs_", "")
            if month_str < cutoff_month:
                cur = self._conn.execute(f"SELECT COUNT(*) FROM {table}")
                cnt = cur.fetchone()[0]
                deleted_rows += cnt
                self._conn.execute(f"DROP TABLE IF EXISTS {table}")
                tables_dropped.append(table)

        if tables_dropped:
            self._table_cache -= set(tables_dropped)
            self._rebuild_view()
            self._conn.commit()

        return deleted_rows

    # ---- 基础查询 ----
    def count(self) -> int:
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM logs_all")
            return cur.fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    def time_range(self) -> Optional[Tuple[float, float]]:
        try:
            cur = self._conn.execute("SELECT MIN(ts), MAX(ts) FROM logs_all")
            row = cur.fetchone()
            if row[0] is None:
                return None
            return (row[0], row[1])
        except sqlite3.OperationalError:
            return None

    def iter_all(self):
        try:
            cur = self._conn.execute(
                "SELECT ts, subject, action, resource, status, source_file FROM logs_all ORDER BY ts"
            )
            for r in cur:
                yield dict(r)
        except sqlite3.OperationalError:
            return

    # ---- 多维聚合查询 ----
    def group_by_subject(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT subject,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   COUNT(DISTINCT action) AS action_types,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM logs_all
            GROUP BY subject
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql)]
        except sqlite3.OperationalError:
            return []

    def group_by_action(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT action,
                   COUNT(*) AS cnt,
                   COUNT(DISTINCT subject) AS subject_cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM logs_all
            GROUP BY action
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql)]
        except sqlite3.OperationalError:
            return []

    def group_by_status(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT status, COUNT(*) AS cnt
            FROM logs_all
            GROUP BY status
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql)]
        except sqlite3.OperationalError:
            return []

    def group_by_time_window(self, window_seconds: int) -> List[Dict[str, Any]]:
        sql = f"""
            SELECT CAST(ts / {window_seconds} AS INTEGER) AS bucket,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   COUNT(DISTINCT subject) AS subject_cnt,
                   COUNT(DISTINCT action) AS action_cnt,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM logs_all
            GROUP BY bucket
            ORDER BY bucket
        """
        try:
            return [dict(r) for r in self._conn.execute(sql)]
        except sqlite3.OperationalError:
            return []

    def group_by_subject_action(self) -> List[Dict[str, Any]]:
        sql = """
            SELECT subject, action, COUNT(*) AS cnt, MIN(ts) AS t_min, MAX(ts) AS t_max
            FROM logs_all
            GROUP BY subject, action
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql)]
        except sqlite3.OperationalError:
            return []

    def subject_action_time_series(self, window_seconds: int) -> List[Dict[str, Any]]:
        sql = f"""
            SELECT CAST(ts / {window_seconds} AS INTEGER) AS bucket,
                   subject,
                   action,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min
            FROM logs_all
            GROUP BY bucket, subject, action
            ORDER BY bucket, cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql)]
        except sqlite3.OperationalError:
            return []

    def list_month_tables(self) -> List[str]:
        return _known_month_tables(self._conn)

    def query(self, sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
