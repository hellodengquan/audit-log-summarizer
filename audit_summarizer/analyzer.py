"""聚合分析与异常检测模块。

功能：
1. 按主体、动作、时间窗多维聚合
2. 识别异常高峰期（多档窗口 + 按业务流量周期匹配基线）
3. 识别不常见操作（频次极低但有意义）
4. 识别批量动作（按主体类别动态计算阈值）
5. 识别高失败率主体
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


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


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


_SUBJECT_CATEGORIES = {
    "human": {"prefixes": ("user", "admin", "operator", "ops_", "alice", "bob", "charlie", "david", "eve", "frank", "grace", "henry", "ivy", "jack", "kate", "leo", "root", "test")},
    "service": {"prefixes": ("svc_", "service", "cron", "daemon", "system", "agent_", "bot_")},
    "ip": {"prefixes": ()},
}


def _classify_subject(subject: str) -> str:
    low = subject.lower()
    for cat, cfg in _SUBJECT_CATEGORIES.items():
        if cat == "ip":
            continue
        for p in cfg["prefixes"]:
            if low.startswith(p) or low == p:
                return cat
    if _is_ip_like(subject):
        return "ip"
    return "human"


def _is_ip_like(s: str) -> bool:
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


_SUBJECT_CATEGORY_DEFAULTS = {
    "human": {"max_window_seconds": 600, "min_count": 5, "rate_factor": 0.5},
    "service": {"max_window_seconds": 300, "min_count": 20, "rate_factor": 2.0},
    "ip": {"max_window_seconds": 300, "min_count": 10, "rate_factor": 1.0},
}


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
    """基于统计方法识别异常：高峰期、不常见动作、批量操作。"""

    def __init__(self, agg: Aggregator, stats: Dict[str, Any]):
        self.agg = agg
        self.stats = stats

    # ---- 异常高峰期（多档窗口 + 周期基线） ----
    def detect_spikes(self, z_threshold: float = 2.5, min_abs: int = 10) -> List[Dict[str, Any]]:
        """多档窗口分别检测：5min / 1h / 24h，对每档使用「同周期位置基线」做 Z-Score。

        周期基线算法：
        - 5min 窗口：按「小时内的第几个 5min 槽」分组，用同槽位历史均值作基线；
        - 1h 窗口：按「天内的第几小时」分组，用同小时历史均值作基线；
        - 24h 窗口：用全局均值作基线（跨天数据不足时退化为全局基线）。
        """
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
        """按业务流量周期分组计算基线 (mean, stdev)。"""
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

    # ---- 不常见操作 ----
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

    # ---- 批量操作（按主体类别动态阈值） ----
    def detect_bulk_actions(self, max_window_seconds: int = 300, min_count: int = 10,
                            dynamic_threshold: bool = True) -> List[Dict[str, Any]]:
        """同主体+同动作在滑动窗口内重复超过阈值判定为批量操作。

        当 dynamic_threshold=True 时：
        - 对每个 (subject, action) 组合，先统计该 subject 的总操作数和动作种类，
          然后根据主体类别（human/service/ip）动态计算 min_count 和 max_window_seconds：
            human:   min_count = max(3, 总操作数 * 0.01),  window = 600s
            service: min_count = max(15, 总操作数 * 0.03), window = 300s
            ip:      min_count = max(8, 总操作数 * 0.02),  window = 300s
        - 还考虑动作类型的平均频率作为倍数参考。
        """
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
            cat = _classify_subject(subject) if dynamic_threshold else "human"
            defaults = _SUBJECT_CATEGORY_DEFAULTS.get(cat, _SUBJECT_CATEGORY_DEFAULTS["human"])

            if dynamic_threshold:
                s_info = subject_stats.get(subject, {})
                s_total = s_info.get("cnt", 0)
                effective_window = defaults["max_window_seconds"]
                if cat == "human":
                    effective_min = max(3, int(s_total * 0.01))
                elif cat == "service":
                    effective_min = max(15, int(s_total * 0.03))
                else:
                    effective_min = max(8, int(s_total * 0.02))

                avg_rate = action_avg.get(action, 0)
                if avg_rate > 0:
                    expected_in_window = avg_rate * effective_window
                    effective_min = max(effective_min, int(expected_in_window * defaults["rate_factor"] * 2))
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

    # ---- 高频失败主体 ----
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
                    "subject_category": _classify_subject(s["subject"]),
                })
        out.sort(key=lambda x: x["fail_ratio"], reverse=True)
        return out

    # ---- 全部检测汇总 ----
    def all_anomalies(self, dynamic_bulk: bool = True) -> Dict[str, Any]:
        return {
            "spikes": self.detect_spikes(),
            "rare_actions": self.detect_rare_actions(),
            "bulk_actions": self.detect_bulk_actions(dynamic_threshold=dynamic_bulk),
            "high_failure_subjects": self.detect_high_failure_subjects(),
        }


def analyze(storage: Storage, window_seconds: Optional[int] = None,
            spike_tiers: Optional[List[int]] = None,
            dynamic_bulk: bool = True) -> Dict[str, Any]:
    """一站式分析入口：聚合 + 异常检测。"""
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
    }
