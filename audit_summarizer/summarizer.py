"""摘要生成模块：输出两份摘要文件（支持分页与排序）。

1. readable_timeline.md - 人类可读时间线（含异常标注）
2. detailed_stats.json  - 结构化详细统计（便于二次消费）

分页参数控制各表格行数上限，排序参数控制列表排序方式。
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .storage import Storage
from .analyzer import analyze, SPIKE_WINDOWS


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


_SORT_KEY_MAP = {
    "count": lambda x: x.get("cnt", x.get("count", 0)),
    "subject": lambda x: x.get("subject", ""),
    "action": lambda x: x.get("action", ""),
    "failures": lambda x: x.get("fail_cnt", x.get("failures", 0)),
    "fail_ratio": lambda x: x.get("fail_ratio", 0),
    "z_score": lambda x: x.get("z_score", 0),
    "share": lambda x: x.get("share", 0),
    "name": lambda x: x.get("subject", x.get("action", "")),
}


def _sort_list(items: List[Dict[str, Any]], sort_by: str, sort_order: str) -> List[Dict[str, Any]]:
    key_fn = _SORT_KEY_MAP.get(sort_by, _SORT_KEY_MAP["count"])
    reverse = sort_order == "desc"
    try:
        return sorted(items, key=key_fn, reverse=reverse)
    except (TypeError, KeyError):
        return items


def _paginate(items: List[Any], page: int, page_size: int) -> List[Any]:
    if page_size <= 0:
        return items
    start = (page - 1) * page_size
    end = start + page_size
    return items[start:end]


def _write_detailed_stats(path: str, analysis: Dict[str, Any],
                          page_size: int = 0, page: int = 1,
                          sort_by: str = "count", sort_order: str = "desc") -> None:
    payload: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": "2.0",
        "pagination": {
            "page": page,
            "page_size": page_size if page_size > 0 else "unlimited",
        },
        "sort": {
            "by": sort_by,
            "order": sort_order,
        },
        "meta": analysis["meta"],
        "overview": analysis["overview"],
        "by_status": analysis["stats"]["by_status"],
    }

    sorted_subjects = _sort_list(analysis["stats"]["by_subject"], sort_by, sort_order)
    sorted_actions = _sort_list(analysis["stats"]["by_action"], sort_by, sort_order)
    sorted_matrix = _sort_list(analysis["stats"]["by_subject_action"], sort_by, sort_order)

    payload["by_subject"] = _paginate(sorted_subjects, page, page_size)
    payload["by_action"] = _paginate(sorted_actions, page, page_size)
    payload["by_subject_action"] = _paginate(sorted_matrix, page, page_size) if page_size > 0 else sorted_matrix[:200]
    payload["time_series"] = analysis["stats"]["by_time_window"]
    payload["anomalies"] = analysis["anomalies"]

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def _write_timeline(path: str, analysis: Dict[str, Any], storage: Storage,
                    page_size: int = 0, page: int = 1,
                    sort_by: str = "count", sort_order: str = "desc") -> None:
    lines: List[str] = []
    meta = analysis["meta"]
    ov = analysis["overview"]

    lines.append("# 审计日志摘要报告")
    lines.append("")
    lines.append(f"> 生成时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if page_size > 0:
        lines.append(f"> 分页：第 {page} 页，每页 {page_size} 条")
    lines.append(f"> 排序：按 {sort_by} {sort_order}")
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

    sorted_subjects = _sort_list(analysis["stats"]["by_subject"], sort_by, sort_order)
    subjects = _paginate(sorted_subjects, page, page_size) if page_size > 0 else sorted_subjects[:20]
    if subjects:
        lines.append(f"## 三、活跃主体{' (第' + str(page) + '页)' if page_size > 0 else ' Top 20'}")
        lines.append("")
        lines.append("| 排名 | 主体 | 总操作 | 失败 | 动作种类 | 首次活动 | 末次活动 |")
        lines.append("|------|------|--------|------|----------|----------|----------|")
        base = (page - 1) * page_size if page_size > 0 else 0
        for i, s in enumerate(subjects, 1):
            lines.append(
                f"| {base + i} | `{s['subject']}` | {s['cnt']:,} | {s['fail_cnt']} | {s['action_types']} | "
                f"{_fmt_ts(s['t_min'])} | {_fmt_ts(s['t_max'])} |"
            )
        lines.append("")

    sorted_actions = _sort_list(analysis["stats"]["by_action"], sort_by, sort_order)
    actions = _paginate(sorted_actions, page, page_size) if page_size > 0 else sorted_actions
    if actions:
        lines.append("## 四、动作类型分布")
        lines.append("")
        max_a = max(a["cnt"] for a in actions) if actions else 1
        lines.append("| 动作 | 数量 | 占比 | 独立主体 | 失败数 | 可视化 |")
        lines.append("|------|------|------|----------|--------|--------|")
        for a in actions:
            ratio = round(a["cnt"] * 100.0 / ov["total_logs"], 2) if ov["total_logs"] else 0
            lines.append(
                f"| `{a['action']}` | {a['cnt']:,} | {ratio}% | {a['subject_cnt']} | {a['fail_cnt']} | "
                f"`{_bar(a['cnt'], max_a)}` |"
            )
        lines.append("")

    anom = analysis["anomalies"]
    lines.append("## 五、异常检测")
    lines.append("")
    total_anom = sum(len(v) for v in anom.values())
    spike_tiers_used = set(s.get("tier_label", "") for s in anom["spikes"]) if anom["spikes"] else set()
    lines.append(f"- 🚨 **异常高峰期**：{len(anom['spikes'])} 处（窗口档位：{', '.join(sorted(spike_tiers_used)) or 'N/A'}）")
    lines.append(f"- 🔍 **不常见操作**：{len(anom['rare_actions'])} 种")
    lines.append(f"- 📦 **批量动作**：{len(anom['bulk_actions'])} 起（动态阈值）")
    lines.append(f"- ⚠️  **高失败主体**：{len(anom['high_failure_subjects'])} 个")
    lines.append(f"- 合计 **{total_anom}** 条异常线索")
    lines.append("")

    if anom["spikes"]:
        lines.append("### 5.1 异常高峰期（多档窗口 Z-Score 突增）")
        lines.append("")
        lines.append("| 起始 | 结束 | 条数 | 基线 | Z-Score | 倍数 | 窗口档 | 涉及主体 | 动作数 | 失败 |")
        lines.append("|------|------|------|------|---------|------|--------|----------|--------|------|")
        for s in anom["spikes"]:
            mult = f"{s['multiplier']}x" if s["multiplier"] else "N/A"
            tier = s.get("tier_label", "")
            lines.append(
                f"| {s['start']} | {s['end']} | {s['count']:,} | {s['baseline']} | "
                f"{s['z_score']} | {mult} | {tier} | {s['subjects_involved']} | {s['action_types']} | {s['failures']} |"
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
        lines.append("### 5.3 批量操作（动态阈值，按主体类别）")
        lines.append("")
        lines.append("| 主体 | 类别 | 动作 | 次数 | 阈值 | 起始 | 结束 | 实际跨度 | 速率/秒 | 占比% |")
        lines.append("|------|------|------|------|------|------|------|----------|---------|-------|")
        for b in anom["bulk_actions"]:
            rate = b["avg_per_second"] if b["avg_per_second"] is not None else "N/A"
            cat = b.get("subject_category", "")
            dyn_min = b.get("dynamic_min_count", "")
            lines.append(
                f"| `{b['subject']}` | {cat} | `{b['action']}` | {b['count']:,} | ≥{dyn_min} | "
                f"{b['start']} | {b['end']} | {_fmt_span(b['actual_span_seconds'])} | {rate} | {b['share']}% |"
            )
        lines.append("")

    if anom["high_failure_subjects"]:
        lines.append("### 5.4 高失败率主体")
        lines.append("")
        lines.append("| 主体 | 类别 | 总操作 | 失败 | 失败率% | 首次 | 末次 |")
        lines.append("|------|------|--------|------|---------|------|------|")
        for h in anom["high_failure_subjects"]:
            cat = h.get("subject_category", "")
            lines.append(
                f"| `{h['subject']}` | {cat} | {h['total']:,} | {h['failures']} | {h['fail_ratio']}% | "
                f"{h['first_seen']} | {h['last_seen']} |"
            )
        lines.append("")

    lines.append("## 六、时间线（按聚合窗口）")
    lines.append("")
    ts_windows = analysis["stats"]["by_time_window"]
    if ts_windows:
        max_cnt = max(w["cnt"] for w in ts_windows)
        spike_starts = {s["start"] for s in anom["spikes"]}
        displayed_windows = _paginate(ts_windows, page, page_size) if page_size > 0 else ts_windows
        lines.append("| 时间窗起始 | 条数 | 主体 | 动作 | 失败 | 可视化 | 标注 |")
        lines.append("|------------|------|------|------|------|--------|------|")
        for w in displayed_windows:
            start = _fmt_ts(w["t_min"])
            mark = "🚨 峰值" if start in spike_starts else ""
            lines.append(
                f"| {start} | {w['cnt']:,} | {w['subject_cnt']} | {w['action_cnt']} | "
                f"{w['fail_cnt']} | `{_bar(w['cnt'], max_cnt, 40)}` | {mark} |"
            )
        if page_size > 0 and len(ts_windows) > page_size:
            total_pages = (len(ts_windows) + page_size - 1) // page_size
            lines.append(f"> 显示第 {page}/{total_pages} 页，共 {len(ts_windows)} 个窗口")
        lines.append("")

    sorted_matrix = _sort_list(analysis["stats"]["by_subject_action"], sort_by, sort_order)
    matrix = _paginate(sorted_matrix, page, page_size) if page_size > 0 else sorted_matrix[:30]
    if matrix:
        lines.append(f"## 七、主体 × 动作{' (第' + str(page) + '页)' if page_size > 0 else '（Top 30 组合）'}")
        lines.append("")
        lines.append("| 主体 | 动作 | 次数 | 起始 | 结束 |")
        lines.append("|------|------|------|------|------|")
        for m in matrix:
            lines.append(
                f"| `{m['subject']}` | `{m['action']}` | {m['cnt']:,} | "
                f"{_fmt_ts(m['t_min'])} | {_fmt_ts(m['t_max'])} |"
            )
        lines.append("")

    lines.append("## 八、附录：日志样本（随机 10 条）")
    lines.append("")
    uv = storage.unified_view_name
    samples = storage.query(
        f"SELECT ts, subject, action, resource, status, source_file FROM {uv} ORDER BY RANDOM() LIMIT 10"
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
    spike_tiers: Optional[List[int]] = None,
    dynamic_bulk: bool = True,
    page_size: Optional[int] = None,
    page: int = 1,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
) -> Tuple[str, str, Dict[str, Any]]:
    """生成两份摘要文件，返回 (timeline_path, stats_path, analysis_dict)。

    page_size / sort_by / sort_order 为 None 时从 audit.yaml 配置读取默认值。
    page_size 超过 max_page_size 时自动截断，防止 OOM。
    """
    from .config import get_config
    cfg = get_config()
    if page_size is None:
        page_size = cfg.default_page_size
    if sort_by is None:
        sort_by = cfg.default_sort_by
    if sort_order is None:
        sort_order = cfg.default_sort_order

    max_page_size = cfg.max_page_size
    if max_page_size > 0 and page_size > max_page_size:
        import sys
        print(f"[警告] page_size={page_size} 超过上限 max_page_size={max_page_size}，已自动截断", file=sys.stderr)
        page_size = max_page_size

    os.makedirs(output_dir, exist_ok=True)
    analysis = analyze(storage, window_seconds, spike_tiers, dynamic_bulk)
    timeline_path = os.path.join(output_dir, timeline_name)
    stats_path = os.path.join(output_dir, stats_name)
    _write_timeline(timeline_path, analysis, storage, page_size, page, sort_by, sort_order)
    _write_detailed_stats(stats_path, analysis, page_size, page, sort_by, sort_order)
    return timeline_path, stats_path, analysis
