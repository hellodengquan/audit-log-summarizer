"""SQLite 存储层：按月分表 + 统一视图 + 主体类别表 + TTL 清理。

设计：
- 每个月份一张 logs_YYYYMM 表
- audit_unified_view 封装跨月 UNION ALL 查询（视图名可配置）
- _subject_categories 表存储主体分类规则（运维可动态增删）
- TTL 清理按月表粒度
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

_META_TABLE = """
CREATE TABLE IF NOT EXISTS _meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_MV_INDEX_TEMPLATES = [
    "CREATE INDEX IF NOT EXISTS idx_{table}_ts ON {table}(ts);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_subject ON {table}(subject);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_action ON {table}(action);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_status ON {table}(status);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_subject_ts ON {table}(subject, ts);",
    "CREATE INDEX IF NOT EXISTS idx_{table}_action_ts ON {table}(action, ts);",
]


def _build_monthly_indexes(mv_name: str, tables: List[str], range_months: int = 6) -> List[str]:
    """生成按月边界和查询范围优化的索引。

    - 为每个月的 ts 范围创建分区化索引（部分索引/函数索引）
    - 为最近 N 个月创建高频查询覆盖索引

    SQLite 不支持真正的 PARTIAL INDEX 带变量，这里使用：
    - 提取月份派生列 month_key = CAST(ts / 2592000 AS INTEGER)
    - 在 (month_key, subject, ts) 和 (month_key, action, ts) 上建联合索引
      覆盖跨 6 月范围查询（查询时 month_key IN (...) + ts BETWEEN ... 双条件加速）
    """
    sqls: List[str] = []
    sqls.append(f"CREATE INDEX IF NOT EXISTS idx_{mv_name}_month_ts "
                f"ON {mv_name}(CAST(ts / 2592000 AS INTEGER), ts);")
    sqls.append(f"CREATE INDEX IF NOT EXISTS idx_{mv_name}_month_subject_ts "
                f"ON {mv_name}(CAST(ts / 2592000 AS INTEGER), subject, ts);")
    sqls.append(f"CREATE INDEX IF NOT EXISTS idx_{mv_name}_month_action_ts "
                f"ON {mv_name}(CAST(ts / 2592000 AS INTEGER), action, ts);")
    sqls.append(f"CREATE INDEX IF NOT EXISTS idx_{mv_name}_month_status "
                f"ON {mv_name}(CAST(ts / 2592000 AS INTEGER), status);")
    sqls.append(f"CREATE INDEX IF NOT EXISTS idx_{mv_name}_month_subject_action_ts "
                f"ON {mv_name}(CAST(ts / 2592000 AS INTEGER), subject, action, ts);")
    return sqls


def _build_cross_range_indexes(mv_name: str, range_months: int = 6) -> List[str]:
    """为跨 N 个月高频聚合场景建立特殊覆盖索引。"""
    sqls: List[str] = []
    seconds_per_month = 2592000
    for offset_months in range(range_months):
        suffix = f"m{offset_months}"
        sqls.append(
            f"CREATE INDEX IF NOT EXISTS idx_{mv_name}_{suffix}_subj_act_ts "
            f"ON {mv_name}(subject, action, ts) "
            f"WHERE ts >= (CAST(strftime('%s', 'now') AS REAL) - {(offset_months + 1) * seconds_per_month}) "
            f"  AND ts <  (CAST(strftime('%s', 'now') AS REAL) - {offset_months * seconds_per_month});"
        )
    return sqls

_SUBJECT_CATEGORIES_TABLE = """
CREATE TABLE IF NOT EXISTS _subject_categories (
    category TEXT NOT NULL,
    prefix TEXT NOT NULL,
    max_window_seconds INTEGER NOT NULL DEFAULT 300,
    min_count_base INTEGER NOT NULL DEFAULT 5,
    min_count_ratio REAL NOT NULL DEFAULT 0.01,
    rate_factor REAL NOT NULL DEFAULT 1.0,
    PRIMARY KEY (category, prefix)
);
"""


def _month_table_name(ts: float, prefix: str = "logs_") -> str:
    dt = datetime.fromtimestamp(ts, timezone.utc)
    return f"{prefix}{dt.strftime('%Y%m')}"


def _known_month_tables(conn: sqlite3.Connection, prefix: str = "logs_") -> List[str]:
    esc = prefix.replace("_", "\\_") + "%"
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? ESCAPE '\\' ORDER BY name",
        (esc,)
    )
    pattern = re.compile(r'^' + re.escape(prefix) + r'\d{5,6}$')
    return [row[0] for row in cur if pattern.match(row[0])]


def _ensure_table(conn: sqlite3.Connection, table: str) -> None:
    conn.execute(_LOG_TABLE_SCHEMA.format(table=table))
    for idx_sql in _INDEX_TEMPLATES:
        conn.execute(idx_sql.format(table=table))


def _build_unified_view_sql(tables: List[str], view_name: str) -> str:
    if not tables:
        return f"CREATE VIEW IF NOT EXISTS {view_name} AS SELECT 0 AS id, 0.0 AS ts, '' AS subject, '' AS action, '' AS resource, '' AS status, '' AS source_file, '' AS raw WHERE 0;"
    union = " UNION ALL ".join(f"SELECT * FROM {t}" for t in tables)
    return f"CREATE VIEW IF NOT EXISTS {view_name} AS {union};"


class Storage:
    """SQLite 存储封装（按月分表 + 统一视图/物化表 + 主体类别表 + TTL 清理）。"""

    def __init__(self, db_path: str = ":memory:", ttl_days: Optional[int] = None,
                 table_prefix: Optional[str] = None, unified_view_name: Optional[str] = None,
                 use_materialized_view: Optional[bool] = None):
        self.db_path = db_path
        self.ttl_days = ttl_days

        from .config import get_config
        cfg = get_config()
        self.table_prefix = table_prefix or cfg.table_prefix
        self.unified_view_name = unified_view_name or cfg.unified_view_name
        self.use_materialized_view = use_materialized_view if use_materialized_view is not None else cfg.use_materialized_view
        self._mv_last_refreshed: Optional[float] = None

        is_new = (db_path == ":memory:") or (not os.path.exists(db_path))
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA cache_size=-65536;")
        self._table_cache: set = set()
        self._categories_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._need_mv_refresh = False
        if is_new:
            self._init_system_tables()
            self._seed_categories(cfg)
            self._rebuild_unified_view()

    def _init_system_tables(self) -> None:
        with self._conn:
            self._conn.execute(_META_TABLE)
            self._conn.execute(_SUBJECT_CATEGORIES_TABLE)
            if self.ttl_days is not None:
                self._conn.execute(
                    "INSERT OR REPLACE INTO _meta (key, value) VALUES ('ttl_days', ?)",
                    (str(self.ttl_days),)
                )

    def _seed_categories(self, cfg: Any) -> None:
        cur = self._conn.execute("SELECT COUNT(*) FROM _subject_categories")
        if cur.fetchone()[0] > 0:
            return
        cats = cfg.subject_categories
        rows = []
        for cat_name, cat_def in cats.items():
            raw_prefixes = cat_def.get("prefixes", [])
            prefixes = [p for p in raw_prefixes if isinstance(p, str)]
            bt = cat_def.get("bulk_threshold", {})
            if not isinstance(bt, dict):
                bt = {}
            for p in prefixes:
                rows.append((
                    cat_name, p,
                    bt.get("max_window_seconds", 300),
                    bt.get("min_count_base", 5),
                    bt.get("min_count_ratio", 0.01),
                    bt.get("rate_factor", 1.0),
                ))
            if not prefixes:
                rows.append((
                    cat_name, "",
                    bt.get("max_window_seconds", 300),
                    bt.get("min_count_base", 5),
                    bt.get("min_count_ratio", 0.01),
                    bt.get("rate_factor", 1.0),
                ))
        if rows:
            with self._conn:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO _subject_categories (category, prefix, max_window_seconds, min_count_base, min_count_ratio, rate_factor) VALUES (?, ?, ?, ?, ?, ?)",
                    rows,
                )

    def _rebuild_unified_view(self) -> None:
        """重建统一视图或物化表。"""
        with self._conn:
            tables = _known_month_tables(self._conn, self.table_prefix)
            mv_name = self.unified_view_name
            cur = self._conn.execute(
                "SELECT type FROM sqlite_master WHERE name = ?",
                (mv_name,),
            )
            row = cur.fetchone()
            if row:
                obj_type = row["type"]
                if obj_type == "view":
                    self._conn.execute(f"DROP VIEW IF EXISTS {mv_name};")
                elif obj_type == "table":
                    self._conn.execute(f"DROP TABLE IF EXISTS {mv_name};")
            if self.use_materialized_view:
                self._build_materialized_view(tables)
            else:
                self._conn.execute(_build_unified_view_sql(tables, self.unified_view_name))

    def _build_materialized_view(self, tables: List[str]) -> None:
        """构建物化表（materialized table）并加索引。

        物化表 vs 视图：
        - 优势：支持索引加速跨月查询，复杂聚合更快
        - 劣势：需要定期刷新，占用更多磁盘空间

        索引策略：
        - 基础 6 个索引（ts/subject/action/status/(subject,ts)/(action,ts)）
        - 按月派生的 month_key 联合索引，加速跨 6 月范围查询
        - 可选的按最近 N 月的部分覆盖索引

        注意：调用前必须已 DROP 同名表/视图，且必须在事务中调用
        """
        from .config import get_config
        cfg = get_config()
        mv_name = self.unified_view_name
        range_months = max(1, min(24, int(cfg.mv_query_range_months)))
        monthly_indexes = cfg.mv_monthly_indexes

        if not tables:
            self._conn.execute(f"""
                CREATE TABLE {mv_name} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    source_file TEXT DEFAULT '',
                    raw TEXT DEFAULT ''
                );
            """)
        else:
            self._conn.execute(f"""
                CREATE TABLE {mv_name} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    source_file TEXT DEFAULT '',
                    raw TEXT DEFAULT ''
                );
            """)
            for t in tables:
                self._conn.execute(f"""
                    INSERT INTO {mv_name} (ts, subject, action, resource, status, source_file, raw)
                    SELECT ts, subject, action, resource, status, source_file, raw FROM {t}
                """)
        for idx_sql in _MV_INDEX_TEMPLATES:
            self._conn.execute(idx_sql.format(table=mv_name))
        if monthly_indexes:
            for idx_sql in _build_monthly_indexes(mv_name, tables, range_months):
                try:
                    self._conn.execute(idx_sql)
                except sqlite3.OperationalError:
                    pass
            for idx_sql in _build_cross_range_indexes(mv_name, range_months):
                try:
                    self._conn.execute(idx_sql)
                except sqlite3.OperationalError:
                    pass
        self._mv_last_refreshed = time.time()
        self._conn.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES (?, ?)",
            (f"mv_{mv_name}_last_refresh", str(self._mv_last_refreshed)),
        )

    def refresh_materialized_view(self) -> None:
        """手动刷新物化表。"""
        if self.use_materialized_view:
            self._rebuild_unified_view()

    def _ensure_mv_fresh(self) -> None:
        """确保物化表是最新的（检查脏标记和_meta表记录）。"""
        if not self.use_materialized_view:
            return
        if self._need_mv_refresh:
            self._rebuild_unified_view()
            self._need_mv_refresh = False
            return
        cur = self._conn.execute(
            "SELECT value FROM _meta WHERE key = ?",
            (f"mv_{self.unified_view_name}_last_refresh",),
        )
        row = cur.fetchone()
        if row is None:
            self._rebuild_unified_view()
            self._need_mv_refresh = False

    # ---- 主体类别 CRUD ----
    def get_subject_categories(self, use_cache: bool = True) -> Dict[str, Dict[str, Any]]:
        """从 _subject_categories 表读取全部类别，返回 {category: {prefixes: [...], bulk_threshold: {...}}}。"""
        if use_cache and self._categories_cache is not None:
            return self._categories_cache

        cur = self._conn.execute(
            "SELECT category, prefix, max_window_seconds, min_count_base, min_count_ratio, rate_factor FROM _subject_categories ORDER BY category, prefix"
        )
        result: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"prefixes": [], "bulk_threshold": {}})
        for row in cur:
            cat = row["category"]
            prefix = row["prefix"]
            if prefix:
                result[cat]["prefixes"].append(prefix)
            result[cat]["bulk_threshold"] = {
                "max_window_seconds": row["max_window_seconds"],
                "min_count_base": row["min_count_base"],
                "min_count_ratio": row["min_count_ratio"],
                "rate_factor": row["rate_factor"],
            }

        self._categories_cache = dict(result)
        return self._categories_cache

    def add_subject_category(self, category: str, prefix: str,
                             max_window_seconds: int = 300, min_count_base: int = 5,
                             min_count_ratio: float = 0.01, rate_factor: float = 1.0) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO _subject_categories (category, prefix, max_window_seconds, min_count_base, min_count_ratio, rate_factor) VALUES (?, ?, ?, ?, ?, ?)",
                (category, prefix, max_window_seconds, min_count_base, min_count_ratio, rate_factor),
            )
        self._categories_cache = None
        try:
            from .analyzer import get_pubsub
            pubsub = get_pubsub()
            pubsub.publish("categories_changed", {
                "source": "storage",
                "action": "add",
                "category": category,
                "prefix": prefix,
            })
        except Exception:
            pass

    def remove_subject_category(self, category: str, prefix: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM _subject_categories WHERE category=? AND prefix=?",
            (category, prefix),
        )
        self._conn.commit()
        self._categories_cache = None
        affected = cur.rowcount > 0
        if affected:
            try:
                from .analyzer import get_pubsub
                pubsub = get_pubsub()
                pubsub.publish("categories_changed", {
                    "source": "storage",
                    "action": "remove",
                    "category": category,
                    "prefix": prefix,
                })
            except Exception:
                pass
        return affected

    def invalidate_categories_cache(self) -> None:
        self._categories_cache = None

    # ---- 事务 ----
    @contextmanager
    def transaction(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ---- 数据写入 ----
    def insert_many(self, rows: Iterable[Dict[str, Any]]) -> int:
        sql_template = (
            "INSERT INTO {table} (ts, subject, action, resource, status, source_file, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        by_table: Dict[str, List[Tuple]] = defaultdict(list)
        for r in rows:
            ts = r["ts"]
            table = _month_table_name(ts, self.table_prefix)
            by_table[table].append((
                ts, r["subject"], r["action"],
                r.get("resource", ""), r.get("status", ""),
                r.get("source_file", ""), r.get("raw", ""),
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
            self._rebuild_unified_view()
        elif total > 0 and self.use_materialized_view:
            self._need_mv_refresh = True
        return total

    # ---- TTL 清理 ----
    def purge_expired(self, ttl_days: Optional[int] = None) -> int:
        days = ttl_days or self.ttl_days
        if days is None:
            return 0
        cutoff_ts = time.time() - days * 86400
        cutoff_dt = datetime.fromtimestamp(cutoff_ts, timezone.utc)
        cutoff_month = cutoff_dt.strftime("%Y%m")

        tables = _known_month_tables(self._conn, self.table_prefix)
        deleted_rows = 0
        tables_dropped = []
        for table in tables:
            month_str = table.replace(self.table_prefix, "")
            if month_str < cutoff_month:
                cur = self._conn.execute(f"SELECT COUNT(*) FROM {table}")
                cnt = cur.fetchone()[0]
                deleted_rows += cnt
                self._conn.execute(f"DROP TABLE IF EXISTS {table}")
                tables_dropped.append(table)

        if tables_dropped:
            self._table_cache -= set(tables_dropped)
            self._rebuild_unified_view()
            self._need_mv_refresh = False
            self._conn.commit()
        return deleted_rows

    # ---- 基础查询（走统一视图/物化表） ----
    def _uv(self) -> str:
        self._ensure_mv_fresh()
        return self.unified_view_name

    def _month_key_clause(self, t_min: Optional[float], t_max: Optional[float]) -> str:
        """生成 month_key 过滤子句，利用按月派生索引加速跨月查询。

        当查询带时间范围且 use_materialized_view=True 时，附加该子句让 SQLite
        使用 idx_*_month_* 联合索引，避免全表扫描。
        """
        if t_min is None or t_max is None:
            return ""
        if not self.use_materialized_view:
            return ""
        mk_min = int(t_min // 2592000) - 1
        mk_max = int(t_max // 2592000) + 1
        mk_min = max(mk_min, 0)
        return f" AND CAST(ts / 2592000 AS INTEGER) BETWEEN {mk_min} AND {mk_max}"

    def count(self, t_min: Optional[float] = None, t_max: Optional[float] = None) -> int:
        try:
            uv = self._uv()
            extra = self._month_key_clause(t_min, t_max)
            if t_min is not None and t_max is not None:
                cur = self._conn.execute(
                    f"SELECT COUNT(*) FROM {uv} WHERE ts BETWEEN ? AND ?{extra}",
                    (t_min, t_max)
                )
            elif t_min is not None:
                cur = self._conn.execute(
                    f"SELECT COUNT(*) FROM {uv} WHERE ts >= ?{extra}",
                    (t_min,)
                )
            elif t_max is not None:
                cur = self._conn.execute(
                    f"SELECT COUNT(*) FROM {uv} WHERE ts <= ?{extra}",
                    (t_max,)
                )
            else:
                cur = self._conn.execute(f"SELECT COUNT(*) FROM {uv}")
            return cur.fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    def time_range(self) -> Optional[Tuple[float, float]]:
        try:
            cur = self._conn.execute(f"SELECT MIN(ts), MAX(ts) FROM {self._uv()}")
            row = cur.fetchone()
            if row[0] is None:
                return None
            return (row[0], row[1])
        except sqlite3.OperationalError:
            return None

    def iter_all(self):
        try:
            cur = self._conn.execute(
                f"SELECT ts, subject, action, resource, status, source_file FROM {self._uv()} ORDER BY ts"
            )
            for r in cur:
                yield dict(r)
        except sqlite3.OperationalError:
            return

    # ---- 多维聚合查询 ----
    def group_by_subject(self, t_min: Optional[float] = None, t_max: Optional[float] = None) -> List[Dict[str, Any]]:
        uv = self._uv()
        extra = self._month_key_clause(t_min, t_max)
        where_clause = ""
        params: Tuple = ()
        if t_min is not None and t_max is not None:
            where_clause = f" WHERE ts BETWEEN ? AND ?{extra}"
            params = (t_min, t_max)
        elif t_min is not None:
            where_clause = f" WHERE ts >= ?{extra}"
            params = (t_min,)
        elif t_max is not None:
            where_clause = f" WHERE ts <= ?{extra}"
            params = (t_max,)
        sql = f"""
            SELECT subject,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   COUNT(DISTINCT action) AS action_types,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM {uv}{where_clause}
            GROUP BY subject
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def group_by_action(self, t_min: Optional[float] = None, t_max: Optional[float] = None) -> List[Dict[str, Any]]:
        uv = self._uv()
        extra = self._month_key_clause(t_min, t_max)
        where_clause = ""
        params: Tuple = ()
        if t_min is not None and t_max is not None:
            where_clause = f" WHERE ts BETWEEN ? AND ?{extra}"
            params = (t_min, t_max)
        elif t_min is not None:
            where_clause = f" WHERE ts >= ?{extra}"
            params = (t_min,)
        elif t_max is not None:
            where_clause = f" WHERE ts <= ?{extra}"
            params = (t_max,)
        sql = f"""
            SELECT action,
                   COUNT(*) AS cnt,
                   COUNT(DISTINCT subject) AS subject_cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM {uv}{where_clause}
            GROUP BY action
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def group_by_status(self, t_min: Optional[float] = None, t_max: Optional[float] = None) -> List[Dict[str, Any]]:
        uv = self._uv()
        extra = self._month_key_clause(t_min, t_max)
        where_clause = ""
        params: Tuple = ()
        if t_min is not None and t_max is not None:
            where_clause = f" WHERE ts BETWEEN ? AND ?{extra}"
            params = (t_min, t_max)
        elif t_min is not None:
            where_clause = f" WHERE ts >= ?{extra}"
            params = (t_min,)
        elif t_max is not None:
            where_clause = f" WHERE ts <= ?{extra}"
            params = (t_max,)
        sql = f"""
            SELECT status, COUNT(*) AS cnt
            FROM {uv}{where_clause}
            GROUP BY status
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def group_by_time_window(self, window_seconds: int, t_min: Optional[float] = None, t_max: Optional[float] = None) -> List[Dict[str, Any]]:
        uv = self._uv()
        extra = self._month_key_clause(t_min, t_max)
        where_clause = ""
        params: Tuple = ()
        if t_min is not None and t_max is not None:
            where_clause = f" WHERE ts BETWEEN ? AND ?{extra}"
            params = (t_min, t_max)
        elif t_min is not None:
            where_clause = f" WHERE ts >= ?{extra}"
            params = (t_min,)
        elif t_max is not None:
            where_clause = f" WHERE ts <= ?{extra}"
            params = (t_max,)
        sql = f"""
            SELECT CAST(ts / {window_seconds} AS INTEGER) AS bucket,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min,
                   MAX(ts) AS t_max,
                   COUNT(DISTINCT subject) AS subject_cnt,
                   COUNT(DISTINCT action) AS action_cnt,
                   SUM(CASE WHEN status='failure' OR status='fail' THEN 1 ELSE 0 END) AS fail_cnt
            FROM {uv}{where_clause}
            GROUP BY bucket
            ORDER BY bucket
        """
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def group_by_subject_action(self, t_min: Optional[float] = None, t_max: Optional[float] = None) -> List[Dict[str, Any]]:
        uv = self._uv()
        extra = self._month_key_clause(t_min, t_max)
        where_clause = ""
        params: Tuple = ()
        if t_min is not None and t_max is not None:
            where_clause = f" WHERE ts BETWEEN ? AND ?{extra}"
            params = (t_min, t_max)
        elif t_min is not None:
            where_clause = f" WHERE ts >= ?{extra}"
            params = (t_min,)
        elif t_max is not None:
            where_clause = f" WHERE ts <= ?{extra}"
            params = (t_max,)
        sql = f"""
            SELECT subject, action, COUNT(*) AS cnt, MIN(ts) AS t_min, MAX(ts) AS t_max
            FROM {uv}{where_clause}
            GROUP BY subject, action
            ORDER BY cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def subject_action_time_series(self, window_seconds: int, t_min: Optional[float] = None, t_max: Optional[float] = None) -> List[Dict[str, Any]]:
        uv = self._uv()
        extra = self._month_key_clause(t_min, t_max)
        where_clause = ""
        params: Tuple = ()
        if t_min is not None and t_max is not None:
            where_clause = f" WHERE ts BETWEEN ? AND ?{extra}"
            params = (t_min, t_max)
        elif t_min is not None:
            where_clause = f" WHERE ts >= ?{extra}"
            params = (t_min,)
        elif t_max is not None:
            where_clause = f" WHERE ts <= ?{extra}"
            params = (t_max,)
        sql = f"""
            SELECT CAST(ts / {window_seconds} AS INTEGER) AS bucket,
                   subject,
                   action,
                   COUNT(*) AS cnt,
                   MIN(ts) AS t_min
            FROM {uv}{where_clause}
            GROUP BY bucket, subject, action
            ORDER BY bucket, cnt DESC
        """
        try:
            return [dict(r) for r in self._conn.execute(sql, params)]
        except sqlite3.OperationalError:
            return []

    def list_month_tables(self) -> List[str]:
        return _known_month_tables(self._conn, self.table_prefix)

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
