"""生成多格式测试日志数据，预埋异常供检测。

输出目录 ./sample_logs/ 包含：
  - login_logs.jsonl        结构化登录日志（JSONL），含暴力破解高峰
  - access.log              Nginx 应用访问日志（文本），含批量爬虫请求
  - ops_logs.csv            运维操作日志（CSV），含不常见操作
  - system.log              系统日志（syslog 文本），含 sudo、重启等
"""

import csv
import json
import os
import random
from datetime import datetime, timezone, timedelta


BASE_TS = int(datetime(2026, 6, 16, 0, 0, 0, tzinfo=timezone.utc).timestamp())
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_logs")

random.seed(42)

USERS = [
    "alice", "bob", "charlie", "david", "eve", "frank", "grace", "henry",
    "ivy", "jack", "kate", "leo", "admin", "root", "svc_deploy", "svc_backup",
]
NORMAL_IPS = [f"10.0.{random.randint(1, 5)}.{random.randint(2, 254)}" for _ in range(20)]
ATTACKER_IPS = [f"185.220.101.{i}" for i in range(1, 8)]

ENDPOINTS = [
    "/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v1/login",
    "/api/v1/logout", "/api/v1/reports", "/api/v1/search", "/health",
    "/static/app.js", "/static/style.css", "/dashboard", "/settings",
]
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
HTTP_STATUS = [200, 200, 200, 200, 201, 204, 301, 302, 400, 401, 403, 404, 500]


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def nginx_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def syslog_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%b %d %H:%M:%S")


def gen_login_logs(path: str) -> None:
    """JSONL 登录日志：正常登录 + 暴力破解高峰 + 偶尔失败的 admin。"""
    rows = []
    ts = BASE_TS
    end_ts = BASE_TS + 86400

    # 普通时段登录
    while ts < end_ts:
        if random.random() < 0.18:
            user = random.choice(USERS[:10])
            ip = random.choice(NORMAL_IPS)
            status = "success" if random.random() < 0.95 else "failure"
            rows.append({
                "ts": iso(ts),
                "event": "login",
                "user": user,
                "src_ip": ip,
                "status": status,
                "service": "sso",
                "session_id": f"sess_{random.randint(10**9, 10**10 - 1)}",
            })
        ts += random.randint(20, 90)

    # 2026-06-16 08:00 UTC 附近集中爆发暴力破解（约 5 分钟 400 次失败）
    spike_start = BASE_TS + 8 * 3600
    for i in range(400):
        ts_s = spike_start + i * random.randint(0, 2)
        ip = random.choice(ATTACKER_IPS)
        rows.append({
            "ts": iso(ts_s),
            "event": "login",
            "user": random.choice(["admin", "root", "administrator", "test", "user"]),
            "src_ip": ip,
            "status": "failure",
            "service": "sso",
            "reason": "invalid_credentials",
        })

    # admin 有 8% 的失败率（高失败主体）
    for _ in range(120):
        ts_a = BASE_TS + random.randint(0, 86399)
        rows.append({
            "ts": iso(ts_a),
            "event": "login",
            "user": "admin",
            "src_ip": random.choice(NORMAL_IPS + ATTACKER_IPS[:2]),
            "status": "failure" if random.random() < 0.35 else "success",
            "service": "sso",
        })

    random.shuffle(rows)
    rows.sort(key=lambda r: r["ts"])
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def gen_access_log(path: str) -> None:
    """Nginx 访问日志：正常流量 + 某 IP 的批量 GET 爬虫（半小时 1500 次）。"""
    lines = []
    ts = BASE_TS
    end_ts = BASE_TS + 86400

    while ts < end_ts:
        if random.random() < 0.35:
            ip = random.choice(NORMAL_IPS)
            method = random.choices(METHODS, weights=[60, 20, 8, 5, 7])[0]
            ep = random.choice(ENDPOINTS)
            code = random.choice(HTTP_STATUS)
            ua = random.choice([
                "Mozilla/5.0 Chrome/124",
                "Mozilla/5.0 Firefox/125",
                "Safari/17.0",
                "curl/8.0",
            ])
            lines.append(
                f'{ip} - - [{nginx_ts(ts)}] "{method} {ep} HTTP/1.1" {code} '
                f'{random.randint(100, 50000)} "-" "{ua}"'
            )
        ts += random.randint(1, 12)

    # 爬虫批量时段：14:00 开始，单 IP 半小时 1500 次 /api/v1/products GET
    spider_ip = "45.33.32.156"
    bulk_start = BASE_TS + 14 * 3600
    for i in range(1500):
        ts_b = bulk_start + i * random.randint(0, 2)
        lines.append(
            f'{spider_ip} - - [{nginx_ts(ts_b)}] "GET /api/v1/products?page={i}&size=50 HTTP/1.1" 200 '
            f'{random.randint(2000, 15000)} "-" "python-requests/2.31"'
        )

    random.shuffle(lines)
    lines.sort(key=lambda l: l.split("[")[1] if "[" in l else "")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def gen_ops_logs(path: str) -> None:
    """运维 CSV 日志：常见部署/重启 + 少量不常见操作（rollback、key_rotate 等）。"""
    ops = [
        ("deploy", 200), ("restart", 120), ("config_change", 60), ("backup", 40),
        ("ssh", 80), ("sudo", 150), ("create", 50), ("delete", 30),
        ("read", 200), ("write", 120),
        # 不常见操作
        ("rollback", 3), ("key_rotate", 2), ("emergency_shutdown", 1),
        ("db_restore", 2), ("cert_revoke", 1), ("permission_grant_global", 4),
    ]
    rows = []
    for action, count in ops:
        for _ in range(count):
            ts = BASE_TS + random.randint(0, 86399)
            operator = random.choice(["ops_alice", "ops_bob", "ops_charlie", "svc_deploy"])
            rows.append({
                "timestamp": iso(ts),
                "operator": operator,
                "action": action,
                "target": random.choice([
                    "prod-web-01", "prod-web-02", "prod-db-master", "prod-db-slave",
                    "staging-api", "prod-cache-01", "prod-mq-01",
                ]),
                "result": "success" if random.random() < 0.9 else "failure",
                "duration_ms": random.randint(10, 60000),
            })
    rows.sort(key=lambda r: r["timestamp"])
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["timestamp", "operator", "action", "target", "result", "duration_ms"])
        w.writeheader()
        for r in rows:
            w.writerow(r)


def gen_system_log(path: str) -> None:
    """syslog 文本：含 sudo、password_change、download 等混合。"""
    lines = []
    ts = BASE_TS
    end_ts = BASE_TS + 86400
    hosts = ["prod-web-01", "prod-web-02", "prod-db-master", "staging-api"]

    while ts < end_ts:
        if random.random() < 0.08:
            host = random.choice(hosts)
            user = random.choice(USERS[:8])
            evt_type = random.choices(
                ["sudo", "su", "passwd", "ssh", "reboot", "cron", "kernel", "daemon"],
                weights=[30, 10, 5, 25, 3, 15, 5, 7],
            )[0]
            if evt_type == "sudo":
                cmd = random.choice(["apt-get update", "systemctl restart nginx", "cat /etc/shadow", "useradd"])
                lines.append(f"{syslog_ts(ts)} {host} sudo: pam_unix(sudo:session): session opened for user {user} by root(uid=0)")
                lines.append(f"{syslog_ts(ts)} {host} sudo:  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
            elif evt_type == "su":
                target = random.choice(["root", "admin"])
                lines.append(f"{syslog_ts(ts)} {host} su[12{random.randint(10,99)}]: pam_unix(su:auth): authentication failure; logname={user} uid=1000 euid=0 tty=pts/0 ruser={user} rhost=  user={target}")
            elif evt_type == "passwd":
                lines.append(f"{syslog_ts(ts)} {host} passwd: pam_unix(passwd:chauthtok): password changed for {user}")
            elif evt_type == "ssh":
                ip = random.choice(NORMAL_IPS + ATTACKER_IPS)
                status = random.choice(["Accepted", "Failed"])
                lines.append(f"{syslog_ts(ts)} {host} sshd[{random.randint(1000,9999)}]: {status} password for {user} from {ip} port {random.randint(1024,65535)} ssh2")
            elif evt_type == "reboot":
                lines.append(f"{syslog_ts(ts)} {host} systemd[1]: Started Reboot.")
                lines.append(f"{syslog_ts(ts)} {host} systemd[1]: Reached target Shutdown.")
            elif evt_type == "cron":
                lines.append(f"{syslog_ts(ts)} {host} CRON[{random.randint(1000,9999)}]: ({user}) CMD (/usr/local/bin/backup.sh daily)")
            elif evt_type == "kernel":
                lines.append(f"{syslog_ts(ts)} {host} kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC={random.choice(ATTACKER_IPS)} DST=10.0.1.5 LEN=40 TOS=0x00 PREC=0x00 TTL=241 ID=54321 PROTO=TCP SPT={random.randint(1024,65535)} DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0")
            else:
                lines.append(f"{syslog_ts(ts)} {host} systemd[1]: Started nginx.service - A high performance web server and a reverse proxy server.")
        ts += random.randint(2, 35)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    gen_login_logs(os.path.join(OUT_DIR, "login_logs.jsonl"))
    gen_access_log(os.path.join(OUT_DIR, "access.log"))
    gen_ops_logs(os.path.join(OUT_DIR, "ops_logs.csv"))
    gen_system_log(os.path.join(OUT_DIR, "system.log"))
    total = 0
    for fn in os.listdir(OUT_DIR):
        fp = os.path.join(OUT_DIR, fn)
        with open(fp, "r", encoding="utf-8") as fh:
            n = sum(1 for _ in fh)
        total += n
        print(f"  · {fn}: {n} 行")
    print(f"合计 {total} 条样例行")


if __name__ == "__main__":
    main()
