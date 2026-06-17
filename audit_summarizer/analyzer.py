"""聚合分析与异常检测模块。

功能：
1. 按主体、动作、时间窗多维聚合
2. 识别异常高峰期（相对基线的突增）
3. 识别不常见操作（频次极低但有意义）
4. 识别批量动作（短时间内同主体+同动作重复大量发生）
"""

from __future__ import annotations

import math
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .storage import Storage


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: List[float], mean_v: float) -> float:
    if len(values) < 2:
        return 0.0
    var = sum((v - mean_v) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var)


def _pick_window(total_seconds: float) -> int:
    """根据时间跨度自动挑选合理的聚合窗口（秒）。"""
    if total_seconds <= 300:
        return 10
    if total_seconds <= 3600:
        return 60
    if total_seconds <= 86400:
        return 300
    if total_seconds <= 86400 * 7:
        return 3600
    return 86400


# ---------------------------------------------------------------------------
# 聚合分析核心
# ---------------------------------------------------------------------------

class Aggregator:
    """负责从 Storage 中抽取多维度聚合结果。"""

    def __init__(self, storage: Storage, window_seconds: Optional[int] = None):
        self.storage = storage
        tr = storage.time_range()
        if tr is None:
            raise ValueError("存储中无数据，无法聚合")
        self.t_min, self.t_max = tr
        self.span = max(self.t_max - self.t_min, 1.0)
        self.window = window_seconds or _pick_window(self.span)

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
    """基于统计方法识别异常：高峰期、不常见动作、批量操作。"""

    def __init__(self, agg: Aggregator, stats: Dict[str, Any]):
        self.agg = agg
        self.stats = stats

    # ---- 异常高峰期 ----
    def detect_spikes(self, z_threshold: float = 2.5, min_abs: int = 10) -> List[Dict[str, Any]]:
        """使用 Z-Score 识别请求量异常高的时间窗。"""
        buckets = self.stats["by_time_window"]
        if not buckets:
            return []
        counts = [float(b["cnt"]) for b in buckets]
        mu = _mean(counts)
        sigma = _stdev(counts, mu)
        spikes = []
        for b in buckets:
            cnt = b["cnt"]
            if sigma > 0:
                z = (cnt - mu) / sigma
            else:
                z = 0.0
            if z >= z_threshold and cnt >= min_abs:
                spikes.append({
                    "start": _fmt_ts(b["t_min"]),
                    "end": _fmt_ts(b["t_max"]),
                    "count": cnt,
                    "baseline": round(mu, 2),
                    "z_score": round(z, 2),
                    "subjects_involved": b["subject_cnt"],
                    "action_types": b["action_cnt"],
                    "failures": b["fail_cnt"],
                    "multiplier": round(cnt / mu, 2) if mu > 0 else None,
                })
        spikes.sort(key=lambda x: x["z_score"], reverse=True)
        return spikes

    # ---- 不常见操作 ----
    def detect_rare_actions(self, percentile: float = 0.1, min_occurrences: int = 1, max_occurrences: Optional[int] = None) -> List[Dict[str, Any]]:
        """识别总体频次处于最低百分位的动作类型，视为不常见操作。"""
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

    # ---- 批量操作（短时间内重复动作） ----
    def detect_bulk_actions(self, max_window_seconds: int = 300, min_count: int = 10) -> List[Dict[str, Any]]:
        """同主体+同动作在滑动窗口内重复 >= min_count 次，判定为批量操作。"""
        series = self.stats["subject_action_ts"]
        if not series:
            return []
        groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for row in series:
            groups[(row["subject"], row["action"])].append(row)

        window_buckets = max(1, int(max_window_seconds / self.agg.window))
        bulks = []
        total = self.stats["total_logs"]
        for (subject, action), rows in groups.items():
            rows.sort(key=lambda r: r["bucket"])
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
                if cur_sum >= min_count:
                    span = 0 if t_min is None or t_max is None else max(t_max - t_min, 0)
                    bulks.append({
                        "subject": subject,
                        "action": action,
                        "count": cur_sum,
                        "window_seconds": max_window_seconds,
                        "actual_span_seconds": round(span, 2),
                        "start": _fmt_ts(t_min) if t_min else "",
                        "end": _fmt_ts(t_max) if t_max else "",
                        "avg_per_second": round(cur_sum / max(span, 1.0), 3) if span else None,
                        "share": round(cur_sum * 100.0 / total, 3) if total else 0.0,
                    })
                    break
        bulks.sort(key=lambda x: x["count"], reverse=True)
        return bulks

    # ---- 高频失败主体（需关注） ----
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
                })
        out.sort(key=lambda x: x["fail_ratio"], reverse=True)
        return out

    # ---- 全部检测汇总 ----
    def all_anomalies(self) -> Dict[str, Any]:
        return {
            "spikes": self.detect_spikes(),
            "rare_actions": self.detect_rare_actions(),
            "bulk_actions": self.detect_bulk_actions(),
            "high_failure_subjects": self.detect_high_failure_subjects(),
        }


def analyze(storage: Storage, window_seconds: Optional[int] = None) -> Dict[str, Any]:
    """一站式分析入口：聚合 + 异常检测。"""
    agg = Aggregator(storage, window_seconds)
    stats = agg.all_stats()
    det = AnomalyDetector(agg, stats)
    anomalies = det.all_anomalies()
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
    }
