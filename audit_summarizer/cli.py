"""命令行入口：从输入目录/文件读取日志 → 入库 → 分析 → 输出摘要。"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import time
from typing import List

from .parser import parse_file
from .storage import Storage
from .summarizer import write_summaries


def _expand_inputs(paths: List[str]) -> List[str]:
    files: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, fnames in os.walk(p):
                for fn in fnames:
                    if fn.startswith("."):
                        continue
                    files.append(os.path.join(root, fn))
        else:
            matched = glob.glob(p)
            if matched:
                files.extend(matched)
            elif os.path.exists(p):
                files.append(p)
    return sorted(set(files))


def _parse_spike_tiers(val: str) -> List[int]:
    parts = val.split(",")
    tiers = []
    for p in parts:
        p = p.strip().lower()
        mapping = {"5min": 300, "1h": 3600, "24h": 86400}
        if p in mapping:
            tiers.append(mapping[p])
        else:
            try:
                tiers.append(int(p))
            except ValueError:
                print(f"[警告] 忽略无效窗口档位 '{p}'", file=sys.stderr)
    return tiers


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit-summarizer",
        description="审计日志摘要工具：聚合日志、识别异常、生成时间线与统计报告",
    )
    p.add_argument("inputs", nargs="+", help="日志文件或目录（支持通配符）")
    p.add_argument(
        "-o", "--output-dir", default="./audit_report",
        help="报告输出目录（默认 ./audit_report）",
    )
    p.add_argument(
        "--db", default=None,
        help="SQLite 数据库路径，默认输出目录下 audit_logs.db；设为 :memory: 用内存库",
    )
    p.add_argument(
        "--window", type=int, default=None,
        help="聚合窗口（秒），未指定则按时间跨度自动选择",
    )
    p.add_argument(
        "--spike-tiers", default="5min,1h,24h",
        help="异常高峰检测窗口档位，逗号分隔（默认 5min,1h,24h），可用 5min/1h/24h 或秒数",
    )
    p.add_argument(
        "--no-dynamic-bulk", action="store_true",
        help="禁用批量动作的动态阈值，退回硬编码阈值",
    )
    p.add_argument(
        "--ttl-days", type=int, default=None,
        help="数据保留天数（TTL），超期月表将被整体删除",
    )
    p.add_argument(
        "--purge", action="store_true",
        help="入库后立即执行 TTL 清理",
    )
    p.add_argument(
        "--batch-size", type=int, default=5000,
        help="批量入库条数（默认 5000）",
    )
    p.add_argument(
        "--page-size", type=int, default=0,
        help="分页大小，0 表示不分页输出全部",
    )
    p.add_argument(
        "--page", type=int, default=1,
        help="输出第几页（需配合 --page-size 使用）",
    )
    p.add_argument(
        "--sort-by", default="count",
        choices=["count", "subject", "action", "failures", "fail_ratio", "z_score", "share", "name"],
        help="排序字段（默认 count）",
    )
    p.add_argument(
        "--sort-order", default="desc",
        choices=["asc", "desc"],
        help="排序方向（默认 desc）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出详细进度",
    )
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    t0 = time.time()
    files = _expand_inputs(args.inputs)
    if not files:
        print("[错误] 未找到任何输入文件", file=sys.stderr)
        return 2

    os.makedirs(args.output_dir, exist_ok=True)
    db_path = args.db if args.db is not None else os.path.join(args.output_dir, "audit_logs.db")

    if args.verbose:
        print(f"[1/5] 发现 {len(files)} 个文件，入库到 {db_path} ...")

    total_parsed = 0
    total_skipped = 0
    storage = Storage(db_path, ttl_days=args.ttl_days)
    try:
        for fpath in files:
            batch = []
            file_count = 0
            file_skip = 0
            try:
                for rec in parse_file(fpath):
                    if rec is None:
                        file_skip += 1
                        continue
                    batch.append(rec)
                    file_count += 1
                    if len(batch) >= args.batch_size:
                        storage.insert_many(batch)
                        batch.clear()
                if batch:
                    storage.insert_many(batch)
                    batch.clear()
            except (OSError, UnicodeDecodeError) as e:
                print(f"[警告] 跳过文件 {fpath}: {e}", file=sys.stderr)
                continue
            total_parsed += file_count
            total_skipped += file_skip
            if args.verbose:
                print(f"  · {os.path.basename(fpath)}: +{file_count} 条，跳过 {file_skip} 条")

        if total_parsed == 0:
            print("[错误] 未能从任何文件解析出有效日志", file=sys.stderr)
            return 3

        if args.verbose:
            print(f"[2/5] 入库完成，共 {total_parsed} 条（跳过 {total_skipped} 条），耗时 {time.time() - t0:.2f}s")

        if args.purge:
            purged = storage.purge_expired()
            if args.verbose:
                print(f"[2.5/5] TTL 清理完成，删除 {purged} 条过期记录")
        else:
            if args.verbose:
                print("[2.5/5] 跳过 TTL 清理")

        if args.verbose:
            print("[3/5] 开始聚合与异常检测 ...")

        spike_tiers = _parse_spike_tiers(args.spike_tiers)
        dynamic_bulk = not args.no_dynamic_bulk

        timeline_path, stats_path, analysis = write_summaries(
            storage=storage,
            output_dir=args.output_dir,
            window_seconds=args.window,
            spike_tiers=spike_tiers,
            dynamic_bulk=dynamic_bulk,
            page_size=args.page_size,
            page=args.page,
            sort_by=args.sort_by,
            sort_order=args.sort_order,
        )

        if args.verbose:
            print(f"[4/5] 生成摘要完成")
            tables = storage.list_month_tables()
            print(f"[5/5] 月表列表：{', '.join(tables) if tables else '(无)'}")

        total = analysis["overview"]["total_logs"]
        meta = analysis["meta"]
        anom = analysis["anomalies"]
        print("")
        print("=" * 60)
        print("  审计日志摘要 完成")
        print("=" * 60)
        print(f"  时间范围 : {meta['start']} → {meta['end']}")
        print(f"  日志总数 : {total:,} 条（{analysis['overview']['unique_subjects']} 主体 / {analysis['overview']['unique_actions']} 动作）")
        print(f"  聚合窗口 : {meta['window_seconds']}s")
        print(f"  高峰档位 : {args.spike_tiers}")
        print(f"  动态阈值 : {'开' if dynamic_bulk else '关'}")
        if args.page_size > 0:
            print(f"  分页     : 第{args.page}页 / 每页{args.page_size}条")
        print(f"  排序     : {args.sort_by} {args.sort_order}")
        print("-" * 60)
        print(f"  🚨 异常高峰期    : {len(anom['spikes'])}")
        print(f"  🔍 不常见操作    : {len(anom['rare_actions'])}")
        print(f"  📦 批量操作      : {len(anom['bulk_actions'])}")
        print(f"  ⚠️  高失败主体    : {len(anom['high_failure_subjects'])}")
        print("-" * 60)
        print(f"  📄 可读时间线    : {os.path.abspath(timeline_path)}")
        print(f"  📊 详细统计 JSON : {os.path.abspath(stats_path)}")
        print("=" * 60)
        return 0

    finally:
        storage.close()


if __name__ == "__main__":
    sys.exit(main())
