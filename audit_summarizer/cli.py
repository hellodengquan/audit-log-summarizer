"""命令行入口：从输入目录/文件读取日志 → 入库 → 分析 → 输出摘要。

支持:
  audit-summarizer analyze ...      # 主分析命令（默认子命令）
  audit-summarizer admin reload ... # 向运行中服务发送热加载
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from typing import List, Optional

from .config import load_config, get_config, set_config, AuditConfig
from .parser import parse_file
from .storage import Storage
from .summarizer import write_summaries
from .analyzer import AdminServer, SPIKE_WINDOWS


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
        if p in SPIKE_WINDOWS:
            tiers.append(SPIKE_WINDOWS[p])
        else:
            try:
                tiers.append(int(p))
            except ValueError:
                print(f"[警告] 忽略无效窗口档位 '{p}'", file=sys.stderr)
    return tiers


def _build_analyze_parser(subparsers=None) -> argparse.ArgumentParser:
    if subparsers:
        p = subparsers.add_parser("analyze", help="分析日志并生成摘要报告")
    else:
        p = argparse.ArgumentParser(
            prog="audit-summarizer",
            description="审计日志摘要工具：聚合日志、识别异常、生成时间线与统计报告",
        )
    p.add_argument("inputs", nargs="+", help="日志文件或目录（支持通配符）")
    p.add_argument("-o", "--output-dir", default="./audit_report", help="报告输出目录")
    p.add_argument("--db", default=None, help="SQLite 数据库路径")
    p.add_argument("--config", default=None, help="audit.yaml 配置文件路径")
    p.add_argument("--window", type=int, default=None, help="聚合窗口（秒）")
    p.add_argument("--spike-tiers", default=None, help="异常高峰窗口档位（覆盖配置）")
    p.add_argument("--no-dynamic-bulk", action="store_true", help="禁用批量动作动态阈值")
    p.add_argument("--ttl-days", type=int, default=None, help="数据保留天数")
    p.add_argument("--purge", action="store_true", help="入库后执行 TTL 清理")
    p.add_argument("--batch-size", type=int, default=5000, help="批量入库条数")
    p.add_argument("--page-size", type=int, default=None, help="分页大小（覆盖配置默认值）")
    p.add_argument("--page", type=int, default=1, help="输出页码")
    p.add_argument("--sort-by", default=None, choices=["count", "subject", "action", "failures", "fail_ratio", "z_score", "share", "name"], help="排序字段（覆盖配置）")
    p.add_argument("--sort-order", default=None, choices=["asc", "desc"], help="排序方向（覆盖配置）")
    p.add_argument("--with-admin", action="store_true", help="启动 /admin/reload HTTP 服务")
    p.add_argument("-v", "--verbose", action="store_true", help="详细进度")
    return p


def _build_admin_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subparsers.add_parser("admin", help="管理命令")
    admin_sub = p.add_subparsers(dest="admin_action")

    reload_p = admin_sub.add_parser("reload", help="向运行中服务发送热加载请求")
    reload_p.add_argument("--host", default="127.0.0.1", help="服务地址")
    reload_p.add_argument("--port", type=int, required=True, help="服务端口")
    reload_p.add_argument("--spike-tiers", default=None, help="新的窗口档位 JSON，如 [\"5min\",\"1h\"]")
    reload_p.add_argument("--add-category", default=None, help="添加类别 JSON，如 '{\"bot\":{\"prefixes\":[\"bot_\"],\"bulk_threshold\":{\"max_window_seconds\":300}}'")
    return p


def build_parser() -> argparse.ArgumentParser:
    main_p = argparse.ArgumentParser(prog="audit-summarizer", description="审计日志摘要工具")
    sub = main_p.add_subparsers(dest="command")
    _build_analyze_parser(sub)
    _build_admin_parser(sub)
    return main_p


def _cmd_analyze(args) -> int:
    cfg = load_config(args.config)
    set_config(cfg)

    t0 = time.time()
    files = _expand_inputs(args.inputs)
    if not files:
        print("[错误] 未找到任何输入文件", file=sys.stderr)
        return 2

    os.makedirs(args.output_dir, exist_ok=True)
    db_path = args.db if args.db is not None else os.path.join(args.output_dir, "audit_logs.db")
    ttl = args.ttl_days if args.ttl_days is not None else cfg.ttl_days

    if args.verbose:
        print(f"[1/5] 发现 {len(files)} 个文件，入库到 {db_path} ...")

    total_parsed = 0
    total_skipped = 0
    storage = Storage(db_path, ttl_days=ttl)
    admin_server: Optional[AdminServer] = None

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

        spike_tiers_str = args.spike_tiers or ",".join(cfg.spike_tiers.keys())
        spike_tiers = _parse_spike_tiers(spike_tiers_str)
        dynamic_bulk = not args.no_dynamic_bulk if args.no_dynamic_bulk else cfg.dynamic_bulk

        page_size = args.page_size
        sort_by = args.sort_by
        sort_order = args.sort_order

        timeline_path, stats_path, analysis = write_summaries(
            storage=storage,
            output_dir=args.output_dir,
            window_seconds=args.window,
            spike_tiers=spike_tiers,
            dynamic_bulk=dynamic_bulk,
            page_size=page_size,
            page=args.page,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        if args.with_admin:
            from .analyzer import AnomalyDetector
            detector = analysis.get("_detector")
            port = cfg.reload_port if cfg.reload_port > 0 else 0
            admin_server = AdminServer(storage, detector, host=cfg.reload_host, port=port)
            actual_port = admin_server.start()
            if args.verbose:
                print(f"[4/5] /admin/reload 服务已启动于 {cfg.reload_host}:{actual_port}")
        else:
            if args.verbose:
                print("[4/5] 生成摘要完成")

        if args.verbose:
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
        print(f"  高峰档位 : {spike_tiers_str}")
        print(f"  动态阈值 : {'开' if dynamic_bulk else '关'}")
        cfg_ps = cfg.default_page_size
        print(f"  配置默认分页 : {cfg_ps if cfg_ps > 0 else '不分页'}")
        print(f"  排序     : {sort_by or cfg.default_sort_by} {sort_order or cfg.default_sort_order}")
        if admin_server:
            print(f"  管理接口 : http://{cfg.reload_host}:{actual_port}/admin/reload")
        print("-" * 60)
        print(f"  🚨 异常高峰期    : {len(anom['spikes'])}")
        print(f"  🔍 不常见操作    : {len(anom['rare_actions'])}")
        print(f"  📦 批量操作      : {len(anom['bulk_actions'])}")
        print(f"  ⚠️  高失败主体    : {len(anom['high_failure_subjects'])}")
        print("-" * 60)
        print(f"  📄 可读时间线    : {os.path.abspath(timeline_path)}")
        print(f"  📊 详细统计 JSON : {os.path.abspath(stats_path)}")
        print("=" * 60)

        if args.with_admin:
            print(f"\n/admin/reload 服务运行中，按 Ctrl+C 退出 ...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                admin_server.stop()

        return 0

    finally:
        if not args.with_admin:
            storage.close()


def _cmd_admin_reload(args) -> int:
    import urllib.request
    import urllib.error

    body: Dict[str, Any] = {}
    if args.spike_tiers:
        try:
            tiers = json.loads(args.spike_tiers)
            body["spike_tiers"] = tiers
        except json.JSONDecodeError:
            print(f"[错误] --spike-tiers JSON 格式无效", file=sys.stderr)
            return 1

    if args.add_category:
        try:
            cat = json.loads(args.add_category)
            body["categories"] = cat
        except json.JSONDecodeError:
            print(f"[错误] --add-category JSON 格式无效", file=sys.stderr)
            return 1

    url = f"http://{args.host}:{args.port}/admin/reload"
    data = json.dumps(body).encode() if body else b"{}"
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
    except urllib.error.URLError as e:
        print(f"[错误] 无法连接到 {url}: {e}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "admin":
        if args.admin_action == "reload":
            return _cmd_admin_reload(args)
        print("[错误] 请指定 admin 子命令，如 admin reload", file=sys.stderr)
        return 1

    if args.command == "analyze" or args.command is None:
        if not hasattr(args, "inputs") or not args.inputs:
            parser.print_help()
            return 1
        return _cmd_analyze(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
