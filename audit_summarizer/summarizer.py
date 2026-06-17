"""摘要生成模块：输出两份摘要文件。

1. readable_timeline.md - 人类可读时间线（含异常标注）
2. detailed_stats.json  - 结构化详细统计（便于二次消费）
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .storage import Storage
from .analyzer import analyze


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_span(sec: float) -> str:
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def _bar(value: int, max_value: int, width: int = 30) -> str:
    if max_value <= 0:
        return ""
    filled = int(round(value * width / max_value))
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


def _build_timeline_events(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """将时间窗、异常、批量操作合并为带标注的时间线事件。"""
    events: List[Dict[str, Any]] = []
    for b in analysis["stats"]["by_time_window"]:
        events.append({
            "ts": b["t_min"],
            "kind": "window",
            "data": b,
        })
    for s in analysis["anomalies"]["spikes"]:
        events.append({
            "ts": s.get("start_ts") or 0,
            "kind": "spike",
            "data": s,
        })
    for bk in analysis["anomalies"]["bulk_actions"]:
        events.append({
            "ts": bk.get("start_ts") or 0,
            "kind": "bulk",
            "data": bk,
        })
    events.sort(key=lambda e: e["ts"])
    return events


def _write_detailed_stats(path: str, analysis: Dict[str, Any]) -> None:
    """写 JSON 详细统计报告。"""
    # 保留所有原始数据结构，原样输出
    payload: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "meta": analysis["meta"],
        "overview": analysis["overview"],
        "by_status": analysis["stats"]["by_status"],
        "by_subject": analysis["stats"]["by_subject"],
        "by_action": analysis["stats"]["by_action"],
        "by_subject_action": analysis["stats"]["by_subject_action"][:200],
        "time_series": analysis["stats"]["by_time_window"],
        "anomalies": analysis["anomalies"],
    }
    # 把大整数时间戳也带回来（meta 里的 start_ts/end_ts 已存在）
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def _write_timeline(path: str, analysis: Dict[str, Any], storage: Storage) -> None:
    """写 Markdown 可读时间线报告。"""
    lines: List[str] = []
    meta = analysis["meta"]
    ov = analysis["overview"]

    # ---- 标题 & 概览 ----
    lines.append("# 审计日志摘要报告")
    lines.append("")
    lines.append(f"> 生成时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## 一、概览")
    lines.append("")
    lines.append(f"- 时间范围：{meta['start']} → {meta['end']}（跨度 {_fmt_span(meta['span_seconds'])}）")
    lines.append(f"- 聚合窗口：{_fmt_span(meta['window_seconds'])}")
    lines.append(f"- 总日志数：**{ov['total_logs']:,}** 条")
    lines.append(f"- 涉及主体：{ov['unique_subjects']} 个")
    lines.append(f"- 动作类型：{ov['unique_actions']} 种")
    lines.append(f"- 时间窗口数：{ov['windows_covered']} 个")
    lines.append("")

    # ---- 状态分布 ----
    statuses = analysis["stats"]["by_status"]
    if statuses:
        lines.append("## 二、状态分布")
        lines.append("")
        max_s = max(s["cnt"] for s in statuses)
        lines.append("| 状态 | 数量 | 占比 | 可视化 |")
        lines.append("|------|------|------|--------|")
        for s in statuses:
            ratio = round(s["cnt"] * 100.0 / ov["total_logs"], 2) if ov["total_logs"] else 0
            lines.append(f"| {s['status'] or '(空)'} | {s['cnt']:,} | {ratio}% | `{_bar(s['cnt'], max_s)}` |")
        lines.append("")

    # ---- Top 主体 ----
    subjects = analysis["stats"]["by_subject"][:20]
    if subjects:
        lines.append("## 三、活跃主体 Top 20")
        lines.append("")
        lines.append("| 排名 | 主体 | 总操作 | 失败 | 动作种类 | 首次活动 | 末次活动 |")
        lines.append("|------|------|--------|------|----------|----------|----------|")
        for i, s in enumerate(subjects, 1):
            lines.append(
                f"| {i} | `{s['subject']}` | {s['cnt']:,} | {s['fail_cnt']} | {s['action_types']} | "
                f"{_fmt_ts(s['t_min'])} | {_fmt_ts(s['t_max'])} |"
            )
        lines.append("")

    # ---- 动作类型分布 ----
    actions = analysis["stats"]["by_action"]
    if actions:
        lines.append("## 四、动作类型分布")
        lines.append("")
        max_a = max(a["cnt"] for a in actions)
        lines.append("| 动作 | 数量 | 占比 | 独立主体 | 失败数 | 可视化 |")
        lines.append("|------|------|------|----------|--------|--------|")
        for a in actions:
            ratio = round(a["cnt"] * 100.0 / ov["total_logs"], 2) if ov["total_logs"] else 0
            lines.append(
                f"| `{a['action']}` | {a['cnt']:,} | {ratio}% | {a['subject_cnt']} | {a['fail_cnt']} | "
                f"`{_bar(a['cnt'], max_a)}` |"
            )
        lines.append("")

    # ---- 异常检测汇总 ----
    anom = analysis["anomalies"]
    lines.append("## 五、异常检测")
    lines.append("")
    total_anom = sum(len(v) for v in anom.values())
    lines.append(f"- 🚨 **异常高峰期**：{len(anom['spikes'])} 处")
    lines.append(f"- 🔍 **不常见操作**：{len(anom['rare_actions'])} 种")
    lines.append(f"- 📦 **批量动作**：{len(anom['bulk_actions'])} 起")
    lines.append(f"- ⚠️  **高失败主体**：{len(anom['high_failure_subjects'])} 个")
    lines.append(f"- 合计 **{total_anom}** 条异常线索")
    lines.append("")

    # --- 异常详情 ---
    if anom["spikes"]:
        lines.append("### 5.1 异常高峰期（Z-Score 突增）")
        lines.append("")
        lines.append("| 起始 | 结束 | 条数 | 基线 | Z-Score | 倍数 | 涉及主体 | 动作数 | 失败 |")
        lines.append("|------|------|------|------|---------|------|----------|--------|------|")
        for s in anom["spikes"]:
            mult = f"{s['multiplier']}x" if s["multiplier"] else "N/A"
            lines.append(
                f"| {s['start']} | {s['end']} | {s['count']:,} | {s['baseline']} | "
                f"{s['z_score']} | {mult} | {s['subjects_involved']} | {s['action_types']} | {s['failures']} |"
            )
        lines.append("")

    if anom["rare_actions"]:
        lines.append("### 5.2 不常见操作（低频但需关注）")
        lines.append("")
        lines.append("| 动作 | 次数 | 占比% | 主体数 | 失败 | 首次 | 末次 |")
        lines.append("|------|------|-------|--------|------|------|------|")
        for r in anom["rare_actions"]:
            lines.append(
                f"| `{r['action']}` | {r['count']} | {r['share']}% | {r['unique_subjects']} | "
                f"{r['failures']} | {r['first_seen']} | {r['last_seen']} |"
            )
        lines.append("")

    if anom["bulk_actions"]:
        lines.append("### 5.3 批量操作（短时高频重复）")
        lines.append("")
        lines.append("| 主体 | 动作 | 次数 | 起始 | 结束 | 实际跨度 | 速率/秒 | 占比% |")
        lines.append("|------|------|------|------|------|----------|---------|-------|")
        for b in anom["bulk_actions"]:
            rate = b["avg_per_second"] if b["avg_per_second"] is not None else "N/A"
            lines.append(
                f"| `{b['subject']}` | `{b['action']}` | {b['count']:,} | {b['start']} | {b['end']} | "
                f"{_fmt_span(b['actual_span_seconds'])} | {rate} | {b['share']}% |"
            )
        lines.append("")

    if anom["high_failure_subjects"]:
        lines.append("### 5.4 高失败率主体")
        lines.append("")
        lines.append("| 主体 | 总操作 | 失败 | 失败率% | 首次 | 末次 |")
        lines.append("|------|--------|------|---------|------|------|")
        for h in anom["high_failure_subjects"]:
            lines.append(
                f"| `{h['subject']}` | {h['total']:,} | {h['failures']} | {h['fail_ratio']}% | "
                f"{h['first_seen']} | {h['last_seen']} |"
            )
        lines.append("")

    # ---- 时间线视图 ----
    lines.append("## 六、时间线（按聚合窗口）")
    lines.append("")
    ts_windows = analysis["stats"]["by_time_window"]
    if ts_windows:
        max_cnt = max(w["cnt"] for w in ts_windows)
        spike_starts = {s["start"] for s in anom["spikes"]}
        lines.append("| 时间窗起始 | 条数 | 主体 | 动作 | 失败 | 可视化 | 标注 |")
        lines.append("|------------|------|------|------|------|--------|------|")
        for w in ts_windows:
            start = _fmt_ts(w["t_min"])
            mark = "🚨 峰值" if start in spike_starts else ""
            lines.append(
                f"| {start} | {w['cnt']:,} | {w['subject_cnt']} | {w['action_cnt']} | "
                f"{w['fail_cnt']} | `{_bar(w['cnt'], max_cnt, 40)}` | {mark} |"
            )
        lines.append("")

    # ---- 主体-动作矩阵 Top ----
    matrix = analysis["stats"]["by_subject_action"][:30]
    if matrix:
        lines.append("## 七、主体 × 动作（Top 30 组合）")
        lines.append("")
        lines.append("| 主体 | 动作 | 次数 | 起始 | 结束 |")
        lines.append("|------|------|------|------|------|")
        for m in matrix:
            lines.append(
                f"| `{m['subject']}` | `{m['action']}` | {m['cnt']:,} | "
                f"{_fmt_ts(m['t_min'])} | {_fmt_ts(m['t_max'])} |"
            )
        lines.append("")

    # ---- 附录：原始样本 ----
    lines.append("## 八、附录：日志样本（随机 10 条）")
    lines.append("")
    samples = storage.query(
        "SELECT ts, subject, action, resource, status, source_file FROM logs ORDER BY RANDOM() LIMIT 10"
    )
    if samples:
        lines.append("| 时间 | 主体 | 动作 | 资源 | 状态 | 来源 |")
        lines.append("|------|------|------|------|------|------|")
        for s in samples:
            res = (s["resource"] or "")[:40]
            lines.append(
                f"| {_fmt_ts(s['ts'])} | `{s['subject']}` | `{s['action']}` | "
                f"{res} | {s['status']} | {s['source_file']} |"
            )
    lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_summaries(
    storage: Storage,
    output_dir: str,
    timeline_name: str = "timeline.md",
    stats_name: str = "stats.json",
    window_seconds: Optional[int] = None,
) -> Tuple[str, str, Dict[str, Any]]:
    """生成两份摘要文件，返回 (timeline_path, stats_path, analysis_dict)。"""
    os.makedirs(output_dir, exist_ok=True)
    analysis = analyze(storage, window_seconds)
    timeline_path = os.path.join(output_dir, timeline_name)
    stats_path = os.path.join(output_dir, stats_name)
    _write_timeline(timeline_path, analysis, storage)
    _write_detailed_stats(stats_path, analysis)
    return timeline_path, stats_path, analysis
