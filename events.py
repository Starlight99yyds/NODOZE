"""事件抽象模块（针对 ndjson 历史日志）。

从 Wazuh/系统 ndjson 日志中解析出“依赖事件”三元组 <SRC, DST, REL>，
并做与实例无关的抽象（去掉时间戳、PID 等），对应论文 NODOZE 的
Dependency Event 定义和实体抽象思想。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Literal, Optional

import json

Relation = Literal["Pro Start", "Pro End", "IP Write", "IP Read"]
EntityType = Literal["process", "socket", "user"]


@dataclass(frozen=True)
class Entity:
    """抽象后的实体（进程 / socket / 用户）。"""

    type: EntityType
    id: str  # 已抽象后的标识，例如 host|program_name 或 外部 IP:port


@dataclass(frozen=True)
class DependencyEvent:
    """依赖事件 E := <SRC, DST, REL>。"""

    src: Entity
    dst: Entity
    rel: Relation
    host: str
    timestamp: str  # 原始时间戳，用于时间窗口划分


def _normalize_hostname(record: dict) -> str:
    pre = record.get("predecoder") or {}
    hostname = pre.get("hostname") or ""
    if not hostname:
        agent = record.get("agent") or {}
        hostname = agent.get("name") or ""
    return hostname or "unknown-host"


def _normalize_process(host: str, record: dict) -> Entity:
    """将主机 + 程序名 抽象为进程实体。"""
    pre = record.get("predecoder") or {}
    prog = pre.get("program_name") or "unknown-proc"
    normalized_id = f"{host}|{prog}"
    return Entity(type="process", id=normalized_id)


def _normalize_socket(record: dict) -> Optional[Entity]:
    """从 sshd / 网络相关日志中抽象 socket 实体（外部 IP:port）。"""
    data = record.get("data") or {}
    srcip = data.get("srcip")
    srcport = data.get("srcport")
    if not srcip:
        return None
    if srcport:
        addr = f"{srcip}:{srcport}"
    else:
        addr = srcip
    return Entity(type="socket", id=addr)


def _normalize_user(record: dict) -> Optional[Entity]:
    """从 PAM / sshd 日志中抽象用户实体。"""
    data = record.get("data") or {}
    user = data.get("dstuser")
    if not user:
        return None
    return Entity(type="user", id=user)


def parse_dependency_events_from_line(line: str) -> List[DependencyEvent]:
    """从一行 ndjson 日志中解析出 0~N 个 DependencyEvent。"""
    line = line.strip()
    if not line:
        return []

    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return []

    host = _normalize_hostname(record)
    rule = record.get("rule") or {}
    decoder = record.get("decoder") or {}
    desc = (rule.get("description") or "").lower()
    decoder_name = (decoder.get("name") or "").lower()
    parent_name = (decoder.get("parent") or "").lower()
    ts = record.get("timestamp") or ""

    events: List[DependencyEvent] = []

    # 1) sshd 认证失败 / 暴力破解 / 无效用户：<host|sshd*, 外部IP:port, IP Write>
    if "sshd" in decoder_name and (
        "authentication failed" in desc
        or "brute force" in desc
        or "invalid user" in desc
        or "invalid_login" in (rule.get("groups") or [])
    ):
        src_proc = _normalize_process(host, record)
        dst_socket = _normalize_socket(record)
        if dst_socket:
            events.append(
                DependencyEvent(
                    src=src_proc,
                    dst=dst_socket,
                    rel="IP Write",
                    host=host,
                    timestamp=ts,
                )
            )
        return events

    data = record.get("data") or {}

    # 2) 进程创建：<parent_proc, child_proc, Pro Start>（形成依赖链）
    if "process_exec" in decoder_name or "process_spawn" in decoder_name:
        parent_prog = data.get("parent_prog")
        child_prog = data.get("child_prog")
        if parent_prog and child_prog:
            src_proc = Entity(type="process", id=f"{host}|{parent_prog}")
            dst_proc = Entity(type="process", id=f"{host}|{child_prog}")
            events.append(
                DependencyEvent(
                    src=src_proc,
                    dst=dst_proc,
                    rel="Pro Start",
                    host=host,
                    timestamp=ts,
                )
            )
            return events

    # 3) 连接接受：<socket, process, IP Read>（客户端 socket 连接到服务端进程）
    if "connection" in decoder_name or "session_accept" in decoder_name:
        dst_socket = _normalize_socket(record)
        if dst_socket:
            src_proc = _normalize_process(host, record)
            events.append(
                DependencyEvent(
                    src=dst_socket,
                    dst=src_proc,
                    rel="IP Read",
                    host=host,
                    timestamp=ts,
                )
            )
            return events

    # 4) PAM session opened/closed：<host|su, user, Pro Start/Pro End>
    if parent_name == "pam" or "pam: login session" in desc:
        src_proc = _normalize_process(host, record)
        dst_user = _normalize_user(record)
        if not dst_user:
            return []

        if "session opened" in desc:
            rel: Relation = "Pro Start"
        elif "session closed" in desc:
            rel = "Pro End"
        else:
            return []

        events.append(
            DependencyEvent(
                src=src_proc,
                dst=dst_user,
                rel=rel,
                host=host,
                timestamp=ts,
            )
        )
        return events

    # 5) 用户发起登录：<user, process, Pro Start>（用户触发 sshd 等进程）
    if "user_login" in decoder_name or "login_init" in decoder_name:
        dst_user = _normalize_user(record)
        if dst_user:
            src_proc = _normalize_process(host, record)
            events.append(
                DependencyEvent(
                    src=dst_user,
                    dst=src_proc,
                    rel="Pro Start",
                    host=host,
                    timestamp=ts,
                )
            )
            return events

    return []


def iter_dependency_events_from_file(path: str) -> Iterable[DependencyEvent]:
    """从 ndjson 文件中流式生成所有抽象后的依赖事件。"""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            for ev in parse_dependency_events_from_line(line):
                yield ev


__all__ = [
    "Entity",
    "DependencyEvent",
    "parse_dependency_events_from_line",
    "iter_dependency_events_from_file",
]

