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
    """展开目录和通配符为具体文件列表。"""
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
        "--batch-size", type=int, default=5000,
        help="批量入库条数（默认 5000）",
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
        print(f"[1/4] 发现 {len(files)} 个文件，入库到 {db_path} ...")

    total_parsed = 0
    total_skipped = 0
    storage = Storage(db_path)
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
            print(f"[2/4] 入库完成，共 {total_parsed} 条（跳过 {total_skipped} 条），耗时 {time.time() - t0:.2f}s")
            print("[3/4] 开始聚合与异常检测 ...")

        timeline_path, stats_path, analysis = write_summaries(
            storage=storage,
            output_dir=args.output_dir,
            window_seconds=args.window,
        )

        if args.verbose:
            print(f"[4/4] 生成摘要完成，总耗时 {time.time() - t0:.2f}s")

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
