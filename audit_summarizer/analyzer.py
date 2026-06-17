"""聚合分析与异常检测模块。

功能：
1. 按主体、动作、时间窗多维聚合
2. 识别异常高峰期（多档窗口 + 按业务流量周期匹配基线）
3. 识别不常见操作（频次极低但有意义）
4. 识别批量动作（按主体类别动态计算阈值，类别从 DB 表加载）
5. 识别高失败率主体
6. /admin/reload 运行时热加载配置
7. pub/sub 事件总线，categories 表变更自动热加载
"""

from __future__ import annotations

import json
import math
import os
import threading
import queue
import time
from collections import defaultdict
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Tuple

from .storage import Storage
from .config import get_config, AuditConfig


# ---------------------------------------------------------------------------
# Pub/Sub 事件总线（进程内，线程安全）
# ---------------------------------------------------------------------------

class _PubSub:
    """轻量级发布订阅，用于 categories 表变更通知 analyzer 热加载。

    支持两种后端：
    - inproc: 进程内内存队列（默认，单机场景）
    - redis:  通过 Redis Sentinel 连接 Redis Cluster（分布式场景，自动故障转移）

    单例模式，通过 get_pubsub() 获取实例。
    Redis 后端依赖可选，未安装 redis 库时自动降级到 inproc。
    """

    CHANNEL_PREFIX = "audit_summarizer:"
    _instance: Optional["_PubSub"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "_PubSub":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subscribers: Dict[str, List[Tuple[int, Callable[[str, Dict[str, Any]], None]]]] = defaultdict(list)
        self._next_id = 0
        self._event_queue: Optional["queue.Queue[Tuple[str, Dict[str, Any]]]"] = None
        self._dispatcher_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        from .config import get_config
        cfg = get_config()
        self._backend = cfg.pubsub_backend
        self._redis_client = None
        self._redis_pubsub = None
        self._redis_listener_thread: Optional[threading.Thread] = None
        self._redis_sentinels = cfg.redis_sentinels
        self._redis_master_name = cfg.redis_master_name
        self._redis_password = cfg.redis_password
        self._redis_db = cfg.redis_db
        self._redis_ready = False

        if self._backend == "redis":
            self._init_redis_backend()

    def _init_redis_backend(self) -> None:
        """初始化 Redis Sentinel 后端，失败时降级到 inproc。"""
        try:
            import redis
            from redis.sentinel import Sentinel
        except ImportError:
            self._backend = "inproc"
            return

        if not self._redis_sentinels:
            self._backend = "inproc"
            return

        try:
            sentinel_nodes = []
            for s in self._redis_sentinels:
                if isinstance(s, dict):
                    host = s.get("host", "127.0.0.1")
                    port = int(s.get("port", 26379))
                    sentinel_nodes.append((host, port))
                elif isinstance(s, str) and ":" in s:
                    host, port_s = s.rsplit(":", 1)
                    sentinel_nodes.append((host, int(port_s)))
                else:
                    sentinel_nodes.append((str(s), 26379))

            if not sentinel_nodes:
                self._backend = "inproc"
                return

            sentinel_kwargs = {
                "socket_timeout": 0.5,
                "socket_connect_timeout": 0.5,
            }
            if self._redis_password:
                sentinel_kwargs["password"] = self._redis_password

            sentinel = Sentinel(sentinel_nodes, **sentinel_kwargs)

            master_kwargs = {"socket_timeout": 1.0, "socket_connect_timeout": 1.0, "db": self._redis_db}
            if self._redis_password:
                master_kwargs["password"] = self._redis_password

            self._redis_client = sentinel.master_for(
                self._redis_master_name, **master_kwargs
            )
            self._redis_client.ping()
            self._redis_pubsub = self._redis_client.pubsub()
            self._redis_ready = True
            self._redis_listener_thread = threading.Thread(
                target=self._redis_listen_loop, daemon=True
            )
            self._redis_listener_thread.start()
        except Exception:
            self._backend = "inproc"
            self._redis_client = None
            self._redis_pubsub = None
            self._redis_ready = False

    def _redis_listen_loop(self) -> None:
        """从 Redis 接收消息并转发到 inproc 订阅者。"""
        try:
            for message in self._redis_pubsub.listen():
                try:
                    if message.get("type") != "message":
                        continue
                    channel = message.get("channel", b"").decode() if isinstance(message.get("channel"), bytes) else str(message.get("channel", ""))
                    topic = channel.replace(self.CHANNEL_PREFIX, "", 1) if channel.startswith(self.CHANNEL_PREFIX) else channel
                    data = message.get("data")
                    if isinstance(data, bytes):
                        data = data.decode()
                    try:
                        payload = json.loads(data) if isinstance(data, str) else {}
                    except json.JSONDecodeError:
                        payload = {}
                    if self._event_queue is not None:
                        self._event_queue.put((topic, payload))
                except Exception:
                    continue
        except Exception:
            self._redis_ready = False

    def subscribe(self, topic: str, callback: Callable[[str, Dict[str, Any]], None]) -> int:
        """订阅主题，返回订阅 ID（用于 unsubscribe）。"""
        with self._lock:
            sid = self._next_id
            self._next_id += 1
            self._subscribers[topic].append((sid, callback))
            self._ensure_dispatcher()
            if self._redis_ready and self._redis_pubsub is not None:
                try:
                    full_channel = f"{self.CHANNEL_PREFIX}{topic}"
                    self._redis_pubsub.subscribe(full_channel)
                except Exception:
                    pass
            return sid

    def unsubscribe(self, subscriber_id: int) -> None:
        """取消订阅。"""
        with self._lock:
            for topic in list(self._subscribers.keys()):
                self._subscribers[topic] = [
                    (sid, cb) for sid, cb in self._subscribers[topic]
                    if sid != subscriber_id
                ]

    def publish(self, topic: str, payload: Optional[Dict[str, Any]] = None) -> None:
        """发布事件到主题（异步分发，不阻塞发布者）。

        Redis 后端：同时发布到 Redis（其他进程可感知）和本地队列（本进程实时处理）。
        Redis 不可用时降级为仅本地。
        """
        if payload is None:
            payload = {}
        if self._event_queue is not None:
            self._event_queue.put((topic, payload))
        if self._redis_ready and self._redis_client is not None:
            try:
                full_channel = f"{self.CHANNEL_PREFIX}{topic}"
                self._redis_client.publish(full_channel, json.dumps(payload))
            except Exception:
                pass

    def _ensure_dispatcher(self) -> None:
        """启动事件分发线程（仅调用一次）。"""
        if self._event_queue is None:
            self._event_queue = queue.Queue()
            self._dispatcher_thread = threading.Thread(
                target=self._dispatch_loop, daemon=True
            )
            self._dispatcher_thread.start()

    def _dispatch_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                topic, payload = self._event_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            with self._lock:
                callbacks = [cb for _, cb in self._subscribers.get(topic, [])]
            for cb in callbacks:
                try:
                    cb(topic, payload)
                except Exception:
                    pass

    def stop(self) -> None:
        self._stop_event.set()
        if self._redis_pubsub is not None:
            try:
                self._redis_pubsub.close()
            except Exception:
                pass
        if self._redis_client is not None:
            try:
                self._redis_client.close()
            except Exception:
                pass


def get_pubsub() -> _PubSub:
    """获取 PubSub 单例。"""
    return _PubSub.get_instance()


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: List[float], mean_v: float) -> float:
    if len(values) < 2:
        return 0.0
    var = sum((v - mean_v) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var)


SPIKE_WINDOWS = {
    "5min": 300,
    "1h": 3600,
    "24h": 86400,
}

_SECONDS_TO_LABEL = {v: k for k, v in SPIKE_WINDOWS.items()}

DEFAULT_SPIKE_TIERS = [300, 3600, 86400]


def _pick_window(total_seconds: float) -> int:
    if total_seconds <= 300:
        return 10
    if total_seconds <= 3600:
        return 60
    if total_seconds <= 86400:
        return 300
    if total_seconds <= 86400 * 7:
        return 3600
    return 86400


def _is_ip_like(s: str) -> bool:
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def _load_categories_from_storage(storage: Storage) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
]:
    """从 _subject_categories 表加载分类规则和阈值参数。

    返回:
        categories: {category: {prefixes: [...]}}
        thresholds: {category: {max_window_seconds, min_count_base, min_count_ratio, rate_factor}}
    """
    cats_db = storage.get_subject_categories(use_cache=False)
    categories: Dict[str, Dict[str, Any]] = {}
    thresholds: Dict[str, Dict[str, Any]] = {}
    for cat_name, cat_data in cats_db.items():
        categories[cat_name] = {"prefixes": cat_data.get("prefixes", [])}
        thresholds[cat_name] = cat_data.get("bulk_threshold", {
            "max_window_seconds": 300,
            "min_count_base": 5,
            "min_count_ratio": 0.01,
            "rate_factor": 1.0,
        })
    if "ip" not in categories:
        categories["ip"] = {"prefixes": []}
        thresholds["ip"] = {"max_window_seconds": 300, "min_count_base": 8, "min_count_ratio": 0.02, "rate_factor": 1.0}
    if "human" not in categories:
        categories["human"] = {"prefixes": []}
        thresholds["human"] = {"max_window_seconds": 600, "min_count_base": 3, "min_count_ratio": 0.01, "rate_factor": 0.5}
    return categories, thresholds


def _classify_subject(subject: str, categories: Dict[str, Dict[str, Any]]) -> str:
    low = subject.lower()
    for cat, cfg in categories.items():
        if cat == "ip":
            continue
        for p in cfg.get("prefixes", []):
            if low.startswith(p) or low == p:
                return cat
    if _is_ip_like(subject):
        return "ip"
    return "human"


# ---------------------------------------------------------------------------
# 聚合分析核心
# ---------------------------------------------------------------------------

class Aggregator:
    """负责从 Storage 中抽取多维度聚合结果。"""

    def __init__(self, storage: Storage, window_seconds: Optional[int] = None,
                 spike_tiers: Optional[List[int]] = None):
        self.storage = storage
        tr = storage.time_range()
        if tr is None:
            raise ValueError("存储中无数据，无法聚合")
        self.t_min, self.t_max = tr
        self.span = max(self.t_max - self.t_min, 1.0)
        self.window = window_seconds or _pick_window(self.span)
        self.spike_tiers = spike_tiers or list(DEFAULT_SPIKE_TIERS)
        self._tier_caches: Dict[int, List[Dict[str, Any]]] = {}

    def _get_tier_buckets(self, tier_seconds: int) -> List[Dict[str, Any]]:
        if tier_seconds not in self._tier_caches:
            self._tier_caches[tier_seconds] = self.storage.group_by_time_window(tier_seconds)
        return self._tier_caches[tier_seconds]

    def all_stats(self) -> Dict[str, Any]:
        return {
            "time_range": {
                "start_ts": self.t_min,
                "end_ts": self.t_max,
                "start": _fmt_ts(self.t_min),
                "end": _fmt_ts(self.t_max),
                "span_seconds": round(self.span, 2),
                "window_seconds": self.window,
            },
            "total_logs": self.storage.count(),
            "by_subject": self.storage.group_by_subject(),
            "by_action": self.storage.group_by_action(),
            "by_status": self.storage.group_by_status(),
            "by_time_window": self.storage.group_by_time_window(self.window),
            "by_subject_action": self.storage.group_by_subject_action(),
            "subject_action_ts": self.storage.subject_action_time_series(self.window),
        }


# ---------------------------------------------------------------------------
# 异常检测器
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """基于统计方法识别异常。主体分类规则从 DB 表动态加载。"""

    def __init__(self, agg: Aggregator, stats: Dict[str, Any]):
        self.agg = agg
        self.stats = stats
        self._categories, self._thresholds = _load_categories_from_storage(agg.storage)
        self._pubsub_sid: Optional[int] = None
        self._subscribe_pubsub()

    def _subscribe_pubsub(self) -> None:
        """订阅 categories_changed 事件，自动热加载。"""
        try:
            from .analyzer import get_pubsub
            pubsub = get_pubsub()
            self._pubsub_sid = pubsub.subscribe(
                "categories_changed",
                self._on_categories_changed,
            )
        except Exception:
            self._pubsub_sid = None

    def _on_categories_changed(self, topic: str, payload: Dict[str, Any]) -> None:
        """收到 categories_changed 事件时自动 reload。"""
        try:
            self.reload_categories()
        except Exception:
            pass

    def reload_categories(self) -> None:
        """重新从 DB 加载主体类别（/admin/reload 触发或 pub/sub 事件触发）。"""
        self.agg.storage.invalidate_categories_cache()
        self._categories, self._thresholds = _load_categories_from_storage(self.agg.storage)

    def close(self) -> None:
        """清理 pub/sub 订阅。"""
        if self._pubsub_sid is not None:
            try:
                from .analyzer import get_pubsub
                pubsub = get_pubsub()
                pubsub.unsubscribe(self._pubsub_sid)
            except Exception:
                pass
            self._pubsub_sid = None

    def detect_spikes(self, z_threshold: float = 2.5, min_abs: int = 10) -> List[Dict[str, Any]]:
        all_spikes: List[Dict[str, Any]] = []
        for tier_sec in self.agg.spike_tiers:
            if self.agg.span < tier_sec:
                continue
            buckets = self.agg._get_tier_buckets(tier_sec)
            if not buckets:
                continue

            if tier_sec < 86400 and self.agg.span >= tier_sec * 2:
                baselines = self._cycle_baselines(buckets, tier_sec)
            else:
                counts = [float(b["cnt"]) for b in buckets]
                global_mu = _mean(counts)
                global_sigma = _stdev(counts, global_mu)
                baselines = {}
                for b in buckets:
                    baselines[b["bucket"]] = (global_mu, global_sigma)

            for b in buckets:
                cnt = b["cnt"]
                if cnt < min_abs:
                    continue
                mu, sigma = baselines.get(b["bucket"], (_mean([float(x["cnt"]) for x in buckets]), 0.0))
                if sigma <= 0:
                    sigma = _stdev([float(x["cnt"]) for x in buckets], mu)
                if sigma <= 0:
                    continue
                z = (cnt - mu) / sigma
                if z >= z_threshold:
                    tier_label = _SECONDS_TO_LABEL.get(tier_sec, f"{tier_sec}s")
                    all_spikes.append({
                        "start": _fmt_ts(b["t_min"]),
                        "end": _fmt_ts(b["t_max"]),
                        "start_ts": b["t_min"],
                        "end_ts": b["t_max"],
                        "count": cnt,
                        "baseline": round(mu, 2),
                        "z_score": round(z, 2),
                        "subjects_involved": b["subject_cnt"],
                        "action_types": b["action_cnt"],
                        "failures": b["fail_cnt"],
                        "multiplier": round(cnt / mu, 2) if mu > 0 else None,
                        "tier_seconds": tier_sec,
                        "tier_label": tier_label,
                    })

        all_spikes.sort(key=lambda x: x["z_score"], reverse=True)
        return all_spikes

    def _cycle_baselines(self, buckets: List[Dict[str, Any]], tier_sec: int) -> Dict[int, Tuple[float, float]]:
        if tier_sec <= 3600:
            slots_per_cycle = max(1, 3600 // tier_sec)
        else:
            slots_per_cycle = max(1, 86400 // tier_sec)
        slot_values: Dict[int, List[float]] = defaultdict(list)
        for b in buckets:
            slot = int(b["bucket"]) % slots_per_cycle
            slot_values[slot].append(float(b["cnt"]))
        baselines: Dict[int, Tuple[float, float]] = {}
        for b in buckets:
            slot = int(b["bucket"]) % slots_per_cycle
            vals = slot_values[slot]
            if len(vals) < 2:
                mu = _mean(vals)
                sigma = _stdev([float(x["cnt"]) for x in buckets], _mean([float(x["cnt"]) for x in buckets]))
            else:
                mu = _mean(vals)
                sigma = _stdev(vals, mu)
            baselines[b["bucket"]] = (mu, sigma)
        return baselines

    def detect_rare_actions(self, percentile: float = 0.1, min_occurrences: int = 1, max_occurrences: Optional[int] = None) -> List[Dict[str, Any]]:
        actions = self.stats["by_action"]
        if not actions:
            return []
        counts = sorted(a["cnt"] for a in actions)
        idx = max(0, int(len(counts) * percentile))
        threshold = counts[idx] if idx < len(counts) else counts[-1]
        if max_occurrences is not None:
            threshold = min(threshold, max_occurrences)
        rare = []
        total = self.stats["total_logs"]
        for a in actions:
            if a["cnt"] <= threshold and a["cnt"] >= min_occurrences:
                rare.append({
                    "action": a["action"],
                    "count": a["cnt"],
                    "unique_subjects": a["subject_cnt"],
                    "share": round(a["cnt"] * 100.0 / total, 4) if total else 0.0,
                    "failures": a["fail_cnt"],
                    "first_seen": _fmt_ts(a["t_min"]),
                    "last_seen": _fmt_ts(a["t_max"]),
                })
        rare.sort(key=lambda x: (x["count"], -x["failures"]))
        return rare

    def detect_bulk_actions(self, max_window_seconds: int = 300, min_count: int = 10,
                            dynamic_threshold: bool = True) -> List[Dict[str, Any]]:
        series = self.stats["subject_action_ts"]
        if not series:
            return []

        subject_stats: Dict[str, Dict[str, Any]] = {}
        for s in self.stats["by_subject"]:
            subject_stats[s["subject"]] = s

        action_avg: Dict[str, float] = {}
        for a in self.stats["by_action"]:
            total = self.stats["total_logs"]
            action_avg[a["action"]] = a["cnt"] / max(self.agg.span, 1.0)

        groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for row in series:
            groups[(row["subject"], row["action"])].append(row)

        bulks = []
        total = self.stats["total_logs"]

        for (subject, action), rows in groups.items():
            cat = _classify_subject(subject, self._categories) if dynamic_threshold else "human"
            bt = self._thresholds.get(cat, self._thresholds.get("human", {
                "max_window_seconds": 600, "min_count_base": 3,
                "min_count_ratio": 0.01, "rate_factor": 0.5,
            }))

            if dynamic_threshold:
                s_info = subject_stats.get(subject, {})
                s_total = s_info.get("cnt", 0)
                effective_window = bt["max_window_seconds"]
                effective_min = max(bt["min_count_base"], int(s_total * bt["min_count_ratio"]))

                avg_rate = action_avg.get(action, 0)
                if avg_rate > 0:
                    expected_in_window = avg_rate * effective_window
                    effective_min = max(effective_min, int(expected_in_window * bt["rate_factor"] * 2))
            else:
                effective_window = max_window_seconds
                effective_min = min_count

            rows.sort(key=lambda r: r["bucket"])
            window_buckets = max(1, int(effective_window / self.agg.window))
            n = len(rows)

            for i in range(n):
                j = i
                cur_sum = 0
                t_min = None
                t_max = None
                while j < n and (rows[j]["bucket"] - rows[i]["bucket"]) <= window_buckets:
                    cur_sum += rows[j]["cnt"]
                    t_min = rows[i]["t_min"] if t_min is None else min(t_min, rows[j]["t_min"])
                    t_max = rows[j]["t_min"] if t_max is None else max(t_max, rows[j]["t_min"])
                    j += 1
                if cur_sum >= effective_min:
                    span = 0 if t_min is None or t_max is None else max(t_max - t_min, 0)
                    bulks.append({
                        "subject": subject,
                        "action": action,
                        "count": cur_sum,
                        "window_seconds": effective_window,
                        "actual_span_seconds": round(span, 2),
                        "start": _fmt_ts(t_min) if t_min else "",
                        "end": _fmt_ts(t_max) if t_max else "",
                        "start_ts": t_min,
                        "end_ts": t_max,
                        "avg_per_second": round(cur_sum / max(span, 1.0), 3) if span else None,
                        "share": round(cur_sum * 100.0 / total, 3) if total else 0.0,
                        "subject_category": cat,
                        "dynamic_min_count": effective_min,
                    })
                    break

        bulks.sort(key=lambda x: x["count"], reverse=True)
        return bulks

    def detect_high_failure_subjects(self, min_fail_ratio: float = 0.2, min_fails: int = 5) -> List[Dict[str, Any]]:
        out = []
        for s in self.stats["by_subject"]:
            total = s["cnt"]
            fails = s["fail_cnt"]
            if fails >= min_fails and (fails / total) >= min_fail_ratio:
                out.append({
                    "subject": s["subject"],
                    "total": total,
                    "failures": fails,
                    "fail_ratio": round(fails * 100.0 / total, 2),
                    "first_seen": _fmt_ts(s["t_min"]),
                    "last_seen": _fmt_ts(s["t_max"]),
                    "subject_category": _classify_subject(s["subject"], self._categories),
                })
        out.sort(key=lambda x: x["fail_ratio"], reverse=True)
        return out

    def all_anomalies(self, dynamic_bulk: bool = True) -> Dict[str, Any]:
        return {
            "spikes": self.detect_spikes(),
            "rare_actions": self.detect_rare_actions(),
            "bulk_actions": self.detect_bulk_actions(dynamic_threshold=dynamic_bulk),
            "high_failure_subjects": self.detect_high_failure_subjects(),
        }


# ---------------------------------------------------------------------------
# Admin Token Secret Rotation（密钥轮换中间件）
# ---------------------------------------------------------------------------

class _SecretRotator:
    """Admin token 自动轮换：定期从轮换文件读取新 token，支持新旧 token 共存。

    使用场景：运维通过部署流水线定期更新 rotation 文件，服务无需重启即可感知新 token。
    """

    def __init__(self, rotation_file: str, interval_seconds: int = 0,
                 allow_old_seconds: int = 3600):
        self.rotation_file = rotation_file
        self.interval_seconds = interval_seconds
        self.allow_old_seconds = allow_old_seconds
        self._lock = threading.RLock()
        self._current_token: Optional[str] = None
        self._token_history: List[Tuple[str, float]] = []
        self._last_file_mtime: Optional[float] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _read_token_from_file(self) -> Optional[str]:
        """从轮换文件读取 token，支持纯文本或 JSON 格式。"""
        if not self.rotation_file or not os.path.exists(self.rotation_file):
            return None
        try:
            with open(self.rotation_file, "r", encoding="utf-8") as fh:
                content = fh.read().strip()
            if not content:
                return None
            if content.startswith("{") or content.startswith("["):
                data = json.loads(content)
                if isinstance(data, dict):
                    for key in ("token", "admin_token", "secret", "value"):
                        if key in data and isinstance(data[key], str):
                            return data[key].strip()
                elif isinstance(data, list) and data and isinstance(data[0], str):
                    return data[0].strip()
            return content
        except (OSError, json.JSONDecodeError):
            return None

    def _reload_if_needed(self) -> None:
        """检测文件变更，更新 token。"""
        try:
            mtime = os.path.getmtime(self.rotation_file) if self.rotation_file and os.path.exists(self.rotation_file) else None
        except OSError:
            mtime = None

        if mtime is None or mtime == self._last_file_mtime:
            return

        token = self._read_token_from_file()
        if token and token != self._current_token:
            now = time.time()
            with self._lock:
                if self._current_token:
                    self._token_history.append((self._current_token, now))
                    cutoff = now - self.allow_old_seconds
                    self._token_history = [
                        (t, ts) for t, ts in self._token_history if ts >= cutoff
                    ]
                self._current_token = token
                self._last_file_mtime = mtime
        elif mtime != self._last_file_mtime:
            self._last_file_mtime = mtime

    def get_valid_tokens(self) -> set:
        """返回当前所有有效 token（包括当前 + 窗口内的历史 token）。"""
        self._reload_if_needed()
        with self._lock:
            now = time.time()
            cutoff = now - self.allow_old_seconds
            self._token_history = [
                (t, ts) for t, ts in self._token_history if ts >= cutoff
            ]
            tokens = set()
            if self._current_token:
                tokens.add(self._current_token)
            for t, _ in self._token_history:
                tokens.add(t)
            return tokens

    def start(self) -> None:
        """启动后台轮询线程（仅当 interval_seconds > 0 时启动）。"""
        if self.interval_seconds <= 0 or self._thread is not None:
            return
        self._reload_if_needed()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._reload_if_needed()
            except Exception:
                pass
            self._stop_event.wait(self.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()


class _ReloadHandler(BaseHTTPRequestHandler):
    storage: Optional[Storage] = None
    detector: Optional[AnomalyDetector] = None
    pubsub: Optional["_PubSub"] = None
    token_rotator: Optional["_SecretRotator"] = None

    def _check_auth(self) -> bool:
        """校验 admin token，支持 token rotation（多 token 同时生效）。"""
        from .config import get_config
        cfg = get_config()

        if self.token_rotator is not None:
            valid_tokens = self.token_rotator.get_valid_tokens()
            expected_token = cfg.admin_token
            if expected_token and expected_token not in valid_tokens:
                valid_tokens.add(expected_token)
        else:
            valid_tokens = set()
            expected_token = cfg.admin_token
            if expected_token:
                valid_tokens.add(expected_token)

        if not valid_tokens:
            return True

        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token = auth_header[7:].strip()
        return token in valid_tokens

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_POST(self):
        if not self._check_auth():
            self._send_json(401, {"error": "unauthorized", "detail": "valid admin token required"})
            return
        if self.path == "/admin/reload":
            self._handle_reload()
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        if self.path in ("/admin/health", "/admin/categories"):
            if not self._check_auth():
                self._send_json(401, {"error": "unauthorized", "detail": "valid admin token required"})
                return
        if self.path == "/admin/health":
            self._send_json(200, {"status": "ok"})
        elif self.path == "/admin/categories":
            self._handle_list_categories()
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_reload(self):
        try:
            cfg = get_config()
            cfg.reload()
            content_len = int(self.headers.get("Content-Length", 0))
            body = {}
            if content_len > 0:
                raw = self.rfile.read(content_len)
                body = json.loads(raw)

            if body.get("spike_tiers"):
                tiers = []
                for t in body["spike_tiers"]:
                    if isinstance(t, int):
                        tiers.append(t)
                    elif isinstance(t, str) and t in SPIKE_WINDOWS:
                        tiers.append(SPIKE_WINDOWS[t])
                if tiers and self.detector:
                    self.detector.agg.spike_tiers = tiers

            if body.get("categories"):
                if self.storage:
                    for cat_name, cat_data in body["categories"].items():
                        prefixes = cat_data.get("prefixes", [])
                        bt = cat_data.get("bulk_threshold", {})
                        for p in prefixes:
                            self.storage.add_subject_category(
                                cat_name, p,
                                bt.get("max_window_seconds", 300),
                                bt.get("min_count_base", 5),
                                bt.get("min_count_ratio", 0.01),
                                bt.get("rate_factor", 1.0),
                            )
                    if self.pubsub:
                        self.pubsub.publish("categories_changed", {"source": "admin_reload"})

            if body.get("refresh_mv") and self.storage:
                if hasattr(self.storage, "refresh_materialized_view"):
                    self.storage.refresh_materialized_view()

            if self.detector:
                self.detector.reload_categories()

            from .parser import _invalidate_pb_schema_cache
            _invalidate_pb_schema_cache()

            self._send_json(200, {
                "status": "reloaded",
                "spike_tiers": self.detector.agg.spike_tiers if self.detector else [],
                "materialized_view_refreshed": bool(body.get("refresh_mv")),
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_list_categories(self):
        if not self.storage:
            self._send_json(500, {"error": "storage not available"})
            return
        cats = self.storage.get_subject_categories(use_cache=False)
        self._send_json(200, cats)

    def log_message(self, format, *args):
        pass


class AdminServer:
    """/admin/reload 轻量 HTTP 服务，支持运行时热加载配置和 secret rotation。"""

    def __init__(self, storage: Storage, detector: Optional[AnomalyDetector] = None,
                 host: str = "127.0.0.1", port: int = 0):
        self.storage = storage
        self.detector = detector
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._pubsub = get_pubsub()
        self._token_rotator: Optional[_SecretRotator] = None

        from .config import get_config
        cfg = get_config()
        rotation_file = cfg.admin_token_rotation_file
        if rotation_file:
            if cfg.config_path and not os.path.isabs(rotation_file):
                base = os.path.dirname(os.path.abspath(cfg.config_path))
                rotation_file = os.path.join(base, rotation_file)
            self._token_rotator = _SecretRotator(
                rotation_file=rotation_file,
                interval_seconds=cfg.admin_token_rotation_interval_seconds,
                allow_old_seconds=cfg.admin_token_allow_old_seconds,
            )

    def start(self) -> int:
        if self._token_rotator:
            self._token_rotator.start()
        handler = type("Handler", (_ReloadHandler,), {
            "storage": self.storage,
            "detector": self.detector,
            "pubsub": self._pubsub,
            "token_rotator": self._token_rotator,
        })
        self._server = HTTPServer((self.host, self.port), handler)
        actual_port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return actual_port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._token_rotator:
            self._token_rotator.stop()
            self._token_rotator = None
        if self.detector:
            self.detector.close()

    def update_detector(self, detector: AnomalyDetector) -> None:
        self.detector = detector
        if self._server:
            if hasattr(self._server, 'RequestHandlerClass'):
                self._server.RequestHandlerClass.detector = detector


# ---------------------------------------------------------------------------
# 一站式入口
# ---------------------------------------------------------------------------

def analyze(storage: Storage, window_seconds: Optional[int] = None,
            spike_tiers: Optional[List[int]] = None,
            dynamic_bulk: bool = True) -> Dict[str, Any]:
    agg = Aggregator(storage, window_seconds, spike_tiers)
    stats = agg.all_stats()
    det = AnomalyDetector(agg, stats)
    anomalies = det.all_anomalies(dynamic_bulk=dynamic_bulk)
    return {
        "meta": stats["time_range"],
        "overview": {
            "total_logs": stats["total_logs"],
            "unique_subjects": len(stats["by_subject"]),
            "unique_actions": len(stats["by_action"]),
            "windows_covered": len(stats["by_time_window"]),
        },
        "stats": stats,
        "anomalies": anomalies,
        "_detector": det,
    }
