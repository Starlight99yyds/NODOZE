#!/usr/bin/env python3
"""
生成 NODOZE 测试数据：
- 大规模正常基线 normal_baseline.ndjson
- 多种攻击场景 ndjson 文件
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "data"

HOSTS = [
    "web-server", "db-server", "api-server", "mail-server", "cache-server",
    "app1", "app2", "worker-01", "worker-02", "monitor", "backup-server",
]
USERS = ["deploy", "oracle", "api", "root", "admin", "devops", "jenkins", "git", "www-data"]
INTERNAL_IPS = ["10.0.1.101", "10.0.1.102", "192.168.1.50", "192.168.1.51"]


def _base_record(ts: str, host: str, rid: str) -> dict:
    return {
        "timestamp": ts,
        "agent": {"id": "001", "name": host},
        "manager": {"name": "wazuh.manager"},
        "predecoder": {"hostname": host},
        "location": "custom_processor",
    }


def _write_ndjson(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for i, r in enumerate(records):
            r["id"] = r.get("id", f"{path.stem}.{i:05d}")
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  写入 {len(records)} 条 -> {path}")


def gen_normal_baseline(n_days: int = 14, events_per_day: int = 80) -> None:
    """生成大规模正常基线：多主机、多用户、多日 PAM + freshclam。"""
    records = []
    base_date = datetime(2026, 3, 1)
    fired = 0

    for day in range(n_days):
        d = base_date + timedelta(days=day)
        date_str = d.strftime("%Y-%m-%d")

        # 每小时 freshclam（每主机）
        for hour in range(24):
            ts = f"{date_str}T{hour:02d}:00:00.000+0000"
            for host in HOSTS[:7]:  # 前7台主机有 freshclam
                fired += 1
                records.append({
                    **_base_record(ts, host, "norm"),
                    "rule": {"level": 3, "description": "ClamAV database update", "id": "52507", "firedtimes": fired, "mail": False, "groups": ["clamd", "freshclam", "virus"]},
                    "full_log": f"{d.strftime('%b %d')} {hour:02d}:00:00 {host} freshclam[1001]: ClamAV update process started",
                    "predecoder": {"program_name": "freshclam", "timestamp": f"{d.strftime('%b %d')} {hour:02d}:00:00", "hostname": host},
                    "decoder": {"name": "freshclam"},
                })

        # 每日 PAM 登录（模拟运维）
        for _ in range(events_per_day):
            host = random.choice(HOSTS)
            user = random.choice(USERS)
            hour, minute = random.randint(6, 22), random.randint(0, 59)
            ts = f"{date_str}T{hour:02d}:{minute:02d}:00.000+0000"

            # session opened
            fired += 1
            prog = random.choice(["sshd", "su"])
            records.append({
                **_base_record(ts, host, "norm"),
                "rule": {"level": 3, "description": "PAM: Login session opened.", "id": "5501", "firedtimes": fired, "mail": False, "groups": ["pam", "syslog", "authentication_success"]},
                "full_log": f"{d.strftime('%b %d')} {hour:02d}:{minute:02d} {host} {prog}[1001]: pam_unix({prog}-l:session): session opened for user {user}(uid=1000) by (uid=0)",
                "predecoder": {"program_name": prog, "timestamp": f"{d.strftime('%b %d')} {hour:02d}:{minute:02d}", "hostname": host},
                "decoder": {"parent": "pam", "name": "pam"},
                "data": {"dstuser": user, "uid": "1000"},
            })

            # session closed（几分钟后）
            close_min = min(59, minute + random.randint(2, 15))
            ts2 = f"{date_str}T{hour:02d}:{close_min:02d}:00.000+0000"
            fired += 1
            records.append({
                **_base_record(ts2, host, "norm"),
                "rule": {"level": 3, "description": "PAM: Login session closed.", "id": "5502", "firedtimes": fired, "mail": False, "groups": ["pam", "syslog"]},
                "full_log": f"{d.strftime('%b %d')} {hour:02d}:{close_min:02d} {host} {prog}[1001]: pam_unix({prog}-l:session): session closed for user {user}",
                "predecoder": {"program_name": prog, "timestamp": f"{d.strftime('%b %d')} {hour:02d}:{minute:02d}", "hostname": host},
                "decoder": {"parent": "pam", "name": "pam"},
                "data": {"dstuser": user},
            })

    records.sort(key=lambda r: r["timestamp"])
    _write_ndjson(OUT_DIR / "normal_baseline.ndjson", records)


def _sshd_fail_record(ts: str, host: str, ip: str, port: int, user: str, rule_id: str, desc: str, groups: list) -> dict:
    return {
        **_base_record(ts, host, "atk"),
        "rule": {"level": 5 if rule_id == "5760" else 10, "description": desc, "id": rule_id, "firedtimes": 1, "mail": False, "groups": groups},
        "full_log": f"Mar 10 08:00:00 {host} sshd-session[1001]: Failed password for {user} from {ip} port {port} ssh2",
        "predecoder": {"program_name": "sshd-session", "timestamp": "Mar 10 08:00:00", "hostname": host},
        "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": ip, "srcport": str(port), "dstuser": user},
    }


def _invalid_user_record(ts: str, host: str, ip: str, port: int, user: str) -> dict:
    return {
        **_base_record(ts, host, "atk"),
        "rule": {"level": 5, "description": "sshd: Attempt to login using a non-existent user", "id": "5710", "firedtimes": 1, "mail": False, "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"]},
        "full_log": f"Mar 10 08:00:00 {host} sshd[1001]: Invalid user {user} from {ip} port {port}",
        "predecoder": {"program_name": "sshd", "timestamp": "Mar 10 08:00:00", "hostname": host},
        "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": ip, "srcport": str(port), "srcuser": user},
    }


def gen_attack_ssh_bruteforce() -> None:
    """SSH 暴力破解：单 IP 对单主机多用户尝试。"""
    records = []
    attacker_ip = "45.33.22.11"
    host = "web-server"
    base_ts = "2026-03-15T09:00:00.000+0000"

    for i in range(6):
        ts = f"2026-03-15T09:00:{i*5:02d}.000+0000"
        records.append(_sshd_fail_record(ts, host, attacker_ip, 40000 + i, "root", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))

    records.append(_sshd_fail_record("2026-03-15T09:00:30.000+0000", host, attacker_ip, 40006, "root", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    _write_ndjson(OUT_DIR / "attack_ssh_bruteforce.ndjson", records)


def gen_attack_credential_stuffing() -> None:
    """撞库攻击：多 IP 对多主机尝试常见用户名。"""
    records = []
    ips = ["103.45.67.89", "185.234.219.42", "91.121.88.22"]
    hosts = ["web-server", "db-server", "api-server"]
    users = ["admin", "root", "administrator", "oracle", "deploy"]

    for h, host in enumerate(hosts):
        for u, user in enumerate(users):
            ts = f"2026-03-16T10:{h:02d}:{u*2:02d}.000+0000"
            ip = ips[h % len(ips)]
            records.append(_sshd_fail_record(ts, host, ip, 50000 + h * 100 + u, user, "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))

    records.append(_sshd_fail_record("2026-03-16T10:02:10.000+0000", "db-server", ips[1], 50102, "oracle", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    _write_ndjson(OUT_DIR / "attack_credential_stuffing.ndjson", records)


def gen_attack_recon() -> None:
    """侦察/用户名枚举：大量无效用户尝试。"""
    records = []
    attacker_ip = "198.51.100.23"
    hosts = ["web-server", "api-server", "mail-server"]
    fake_users = ["admin", "root", "test", "guest", "user", "oracle", "postgres", "mysql", "ftp", "nobody", "daemon", "bin", "sys"]

    for h, host in enumerate(hosts):
        for u, user in enumerate(fake_users):
            ts = f"2026-03-17T14:{h:02d}:{u:02d}.000+0000"
            records.append(_invalid_user_record(ts, host, attacker_ip, 60000 + h * 100 + u, user))

    _write_ndjson(OUT_DIR / "attack_recon.ndjson", records)


def gen_attack_lateral_movement() -> None:
    """横向移动：攻击者从 web 入侵后向 db、api 扩散。"""
    records = []
    attacker_ip = "203.0.113.50"
    base = "2026-03-18T11:00:00.000+0000"

    # web-server 暴力破解
    for i in range(5):
        ts = f"2026-03-18T11:00:{i*3:02d}.000+0000"
        records.append(_sshd_fail_record(ts, "web-server", attacker_ip, 70000 + i, "deploy", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))
    records.append(_sshd_fail_record("2026-03-18T11:00:15.000+0000", "web-server", attacker_ip, 70005, "deploy", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    # 成功后 PAM
    records.append({
        **_base_record("2026-03-18T11:01:00.000+0000", "web-server", "atk"),
        "rule": {"level": 3, "description": "PAM: Login session opened.", "id": "5501", "firedtimes": 1, "mail": False, "groups": ["pam", "syslog", "authentication_success"]},
        "full_log": "Mar 18 11:01:00 web-server sshd[1001]: pam_unix(sshd:session): session opened for user deploy(uid=1000) by (uid=0)",
        "predecoder": {"program_name": "sshd", "timestamp": "Mar 18 11:01:00", "hostname": "web-server"},
        "decoder": {"parent": "pam", "name": "pam"},
        "data": {"dstuser": "deploy", "uid": "1000"},
    })

    # 向 db-server 暴力破解
    for i in range(4):
        ts = f"2026-03-18T11:05:{i*2:02d}.000+0000"
        records.append(_sshd_fail_record(ts, "db-server", attacker_ip, 71000 + i, "oracle", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))

    _write_ndjson(OUT_DIR / "attack_lateral_movement.ndjson", records)


def gen_attack_mixed() -> None:
    """混合攻击：无效用户 + 认证失败 + 暴力破解，多主机。"""
    records = []
    ips = ["192.0.2.100", "192.0.2.101"]
    hosts = ["web-server", "db-server", "api-server", "mail-server"]

    idx = 0
    for host in hosts:
        for ip in ips:
            records.append(_invalid_user_record(f"2026-03-19T08:{idx//2:02d}:{(idx%2)*30:02d}.000+0000", host, ip, 80000 + idx, "admin"))
            idx += 1
    for host in hosts[:3]:
        for i in range(3):
            records.append(_sshd_fail_record(f"2026-03-19T09:{i:02d}:00.000+0000", host, ips[0], 80100 + i, "root", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))
    records.append(_sshd_fail_record("2026-03-19T09:03:00.000+0000", "db-server", ips[0], 80103, "oracle", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    _write_ndjson(OUT_DIR / "attack_mixed.ndjson", records)


def gen_attack_complex_chain() -> None:
    """复杂依赖链：含 process_exec、connection 等事件，可形成多节点依赖图。"""
    records = []
    base = "2026-03-20T10:00:00.000+0000"

    def _conn(ts: str, host: str, ip: str, port: int) -> dict:
        return {
            **_base_record(ts, host, "atk"),
            "rule": {"level": 3, "description": "Connection accepted", "id": "8001", "firedtimes": 1, "mail": False, "groups": ["connection"]},
            "full_log": f"{host} sshd: Connection from {ip} port {port}",
            "predecoder": {"program_name": "sshd", "hostname": host},
            "decoder": {"name": "connection"},
            "data": {"srcip": ip, "srcport": str(port)},
        }

    def _proc_spawn(ts: str, host: str, parent: str, child: str) -> dict:
        return {
            **_base_record(ts, host, "atk"),
            "rule": {"level": 3, "description": "Process spawned", "id": "8002", "firedtimes": 1, "mail": False, "groups": ["process"]},
            "full_log": f"{host} {parent}: Forked child {child}",
            "predecoder": {"program_name": parent, "hostname": host},
            "decoder": {"name": "process_exec"},
            "data": {"parent_prog": parent, "child_prog": child},
        }

    # web-server: 连接 -> 进程创建 -> 多次认证失败 -> 暴力破解告警
    records.append(_conn("2026-03-20T10:00:00.000+0000", "web-server", "10.0.0.50", 50001))
    records.append(_proc_spawn("2026-03-20T10:00:01.000+0000", "web-server", "sshd", "sshd-session"))
    for i in range(6):
        ts = f"2026-03-20T10:00:{i+2:02d}.000+0000"
        records.append(_sshd_fail_record(ts, "web-server", "45.33.22.11", 40000 + i, "root", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))
    records.append(_sshd_fail_record("2026-03-20T10:00:08.000+0000", "web-server", "45.33.22.11", 40006, "root", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    # db-server: 另一条链
    records.append(_conn("2026-03-20T10:00:10.000+0000", "db-server", "45.33.22.11", 40010))
    records.append(_proc_spawn("2026-03-20T10:00:11.000+0000", "db-server", "sshd", "sshd-session"))
    records.append(_sshd_fail_record("2026-03-20T10:00:12.000+0000", "db-server", "45.33.22.11", 40011, "oracle", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))
    records.append(_sshd_fail_record("2026-03-20T10:00:13.000+0000", "db-server", "45.33.22.11", 40012, "oracle", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    # PAM 正常登录（增加上下文）
    records.append({
        **_base_record("2026-03-20T10:00:20.000+0000", "web-server", "atk"),
        "rule": {"level": 3, "description": "PAM: Login session opened.", "id": "5501", "firedtimes": 1, "mail": False, "groups": ["pam", "syslog", "authentication_success"]},
        "full_log": "Mar 20 10:00:20 web-server sshd[1001]: pam_unix(sshd-l:session): session opened for user deploy",
        "predecoder": {"program_name": "sshd", "hostname": "web-server"},
        "decoder": {"parent": "pam", "name": "pam"},
        "data": {"dstuser": "deploy"},
    })

    _write_ndjson(OUT_DIR / "attack_complex_chain.ndjson", records)


def gen_attack_complex_graph() -> None:
    """复杂依赖图：10+ 节点，含菱形分支结构，用于测试复杂图可视化。"""
    records = []
    host = "web-server"
    base_ts = "2026-03-21T10:00:00.000+0000"

    def _conn(ts: str, ip: str, port: int) -> dict:
        return {
            **_base_record(ts, host, "atk"),
            "rule": {"level": 3, "description": "Connection accepted", "id": "8001", "firedtimes": 1, "mail": False, "groups": ["connection"]},
            "full_log": f"{host} sshd: Connection from {ip} port {port}",
            "predecoder": {"program_name": "sshd", "hostname": host},
            "decoder": {"name": "connection"},
            "data": {"srcip": ip, "srcport": str(port)},
        }

    def _proc(ts: str, parent: str, child: str) -> dict:
        return {
            **_base_record(ts, host, "atk"),
            "rule": {"level": 3, "description": "Process spawned", "id": "8002", "firedtimes": 1, "mail": False, "groups": ["process"]},
            "full_log": f"{host} {parent}: Forked child {child}",
            "predecoder": {"program_name": parent, "hostname": host},
            "decoder": {"name": "process_exec"},
            "data": {"parent_prog": parent, "child_prog": child},
        }

    def _login(ts: str, user: str) -> dict:
        return {
            **_base_record(ts, host, "atk"),
            "rule": {"level": 3, "description": "User login init", "id": "8003", "firedtimes": 1, "mail": False, "groups": ["login"]},
            "full_log": f"{host} sshd: User {user} initiating connection",
            "predecoder": {"program_name": "sshd", "hostname": host},
            "decoder": {"name": "user_login"},
            "data": {"dstuser": user},
        }

    # 11 节点 + 菱形：user -> sshd <- socket, sshd -> sshd-a & sshd-b -> sshd-c -> ... -> sshd-session -> socket(alert)
    t = 0
    records.append(_login(f"2026-03-21T10:00:{t:02d}.000+0000", "deploy"))
    t += 1
    records.append(_conn(f"2026-03-21T10:00:{t:02d}.000+0000", "10.0.0.1", 50001))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd", "sshd-a"))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd", "sshd-b"))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd-a", "sshd-c"))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd-b", "sshd-c"))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd-c", "sshd-1"))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd-1", "sshd-2"))
    t += 1
    records.append(_proc(f"2026-03-21T10:00:{t:02d}.000+0000", "sshd-2", "sshd-session"))
    t += 1
    records.append(_sshd_fail_record(f"2026-03-21T10:00:{t:02d}.000+0000", host, "45.33.22.11", 40000, "root", "5760", "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"]))
    t += 1
    records.append(_sshd_fail_record(f"2026-03-21T10:00:{t:02d}.000+0000", host, "45.33.22.11", 40001, "root", "5763", "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"]))

    _write_ndjson(OUT_DIR / "attack_complex_graph.ndjson", records)


def gen_large_baseline(target_count: int = 100_000) -> None:
    """生成约 10 万条正常基线，含 PAM、connection、process_exec 等事件类型。"""
    records = []
    base_date = datetime(2026, 1, 1)
    fired = 0

    n_days = 100
    events_per_day = 450  # 100*(168+900)≈10.7万

    for day in range(n_days):
        d = base_date + timedelta(days=day)
        date_str = d.strftime("%Y-%m-%d")

        for hour in range(24):
            ts = f"{date_str}T{hour:02d}:00:00.000+0000"
            for host in HOSTS[:7]:
                fired += 1
                records.append({
                    **_base_record(ts, host, "norm"),
                    "rule": {"level": 3, "description": "ClamAV database update", "id": "52507", "firedtimes": fired, "mail": False, "groups": ["clamd", "freshclam", "virus"]},
                    "full_log": f"{d.strftime('%b %d')} {hour:02d}:00:00 {host} freshclam[1001]: ClamAV update",
                    "predecoder": {"program_name": "freshclam", "hostname": host},
                    "decoder": {"name": "freshclam"},
                })

        for _ in range(events_per_day):
            h = random.choice(HOSTS)
            u = random.choice(USERS)
            hour, minute = random.randint(6, 22), random.randint(0, 59)
            ts = f"{date_str}T{hour:02d}:{minute:02d}:00.000+0000"
            prog = random.choice(["sshd", "su"])

            fired += 1
            records.append({
                **_base_record(ts, h, "norm"),
                "rule": {"level": 3, "description": "PAM: Login session opened.", "id": "5501", "firedtimes": fired, "mail": False, "groups": ["pam", "syslog"]},
                "full_log": f"{h} {prog}[1001]: pam_unix: session opened for user {u}",
                "predecoder": {"program_name": prog, "hostname": h},
                "decoder": {"parent": "pam", "name": "pam"},
                "data": {"dstuser": u},
            })

            close_min = min(59, minute + random.randint(2, 15))
            ts2 = f"{date_str}T{hour:02d}:{close_min:02d}:00.000+0000"
            fired += 1
            records.append({
                **_base_record(ts2, h, "norm"),
                "rule": {"level": 3, "description": "PAM: Login session closed.", "id": "5502", "firedtimes": fired, "mail": False, "groups": ["pam", "syslog"]},
                "full_log": f"{h} {prog}[1001]: pam_unix: session closed for user {u}",
                "predecoder": {"program_name": prog, "hostname": h},
                "decoder": {"parent": "pam", "name": "pam"},
                "data": {"dstuser": u},
            })

        # 每日 connection + process_exec（供频率库统计）
        for _ in range(events_per_day // 10):
            h = random.choice(HOSTS[:5])
            ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
            port = random.randint(40000, 50000)
            hour, minute = random.randint(8, 20), random.randint(0, 59)
            ts = f"{date_str}T{hour:02d}:{minute:02d}:00.000+0000"
            fired += 1
            records.append({
                **_base_record(ts, h, "norm"),
                "rule": {"level": 3, "description": "Connection accepted", "id": "8001", "firedtimes": fired, "mail": False, "groups": ["connection"]},
                "full_log": f"{h} sshd: Connection from {ip} port {port}",
                "predecoder": {"program_name": "sshd", "hostname": h},
                "decoder": {"name": "connection"},
                "data": {"srcip": ip, "srcport": str(port)},
            })
            fired += 1
            records.append({
                **_base_record(ts, h, "norm"),
                "rule": {"level": 3, "description": "Process spawned", "id": "8002", "firedtimes": fired, "mail": False, "groups": ["process"]},
                "full_log": f"{h} sshd: Forked child sshd-session",
                "predecoder": {"program_name": "sshd", "hostname": h},
                "decoder": {"name": "process_exec"},
                "data": {"parent_prog": "sshd", "child_prog": "sshd-session"},
            })

    records.sort(key=lambda r: r["timestamp"])
    _write_ndjson(OUT_DIR / "large_baseline.ndjson", records)
    print(f"  共 {len(records)} 条")


def main() -> None:
    import sys
    print("生成 NODOZE 测试数据...")
    if "--large" in sys.argv:
        print("\n1. 大规模基线 (large_baseline.ndjson, ~10万条)")
        gen_large_baseline(100_000)
    else:
        print("\n1. 正常基线 (normal_baseline.ndjson)")
        gen_normal_baseline(n_days=14, events_per_day=80)
    print("\n2. 攻击场景")
    gen_attack_ssh_bruteforce()
    gen_attack_credential_stuffing()
    gen_attack_recon()
    gen_attack_lateral_movement()
    gen_attack_mixed()
    gen_attack_complex_chain()
    gen_attack_complex_graph()
    print("\n完成。")


if __name__ == "__main__":
    main()
