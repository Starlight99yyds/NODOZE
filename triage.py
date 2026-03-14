"""
NODOZE 告警 Triage 模块（对应论文 Fig.3, Algorithm 1/2/3）。

从 ndjson 中筛选攻击相关告警，构建依赖图，计算异常分数并排序。
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from events import DependencyEvent, parse_dependency_events_from_line

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"


def load_config() -> dict:
    """从 config.json 加载配置，若不存在则返回空字典。"""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

from graph import get_path_anomaly_scores
from scoring import (
    EventFrequencyDB,
    PathScore,
    compute_in_out_scores_for_graph,
    score_path,
)

# 攻击相关告警 rule.id（示例，用于筛选 TDS 候选告警）
ALERT_RULE_IDS = frozenset({
    # SSH/RDP 暴力破解、远程登录、认证失败、无效用户
    5763, 5764, 5760, 5710, 2004, 2597,
    # 端口扫描、SYN 洪水
    6345, 5432, 3333,
    # 恶意软件
    1536, 1234, 8900, 2000,
    # 数据泄露
    1711, 5555, 2001, 5500,
    # 提权、rootkit
    3034, 3025, 3311,
    # SQL 注入、XSS、目录遍历
    1001, 1102, 2503,
    # C&C、后门
    3012, 4444,
    # DoS、暴力破解、DNS 异常、恶意邮件
    1111, 2200, 1325, 1010,
})


def is_alert_record(record: dict) -> bool:
    """判断 ndjson 记录是否为攻击相关告警（rule.id 在 ALERT_RULE_IDS 中）。"""
    rule = record.get("rule") or {}
    rid = rule.get("id")
    if rid is None:
        return False
    try:
        return int(rid) in ALERT_RULE_IDS
    except (TypeError, ValueError):
        return False


def _normalize_hostname(record: dict) -> str:
    pre = record.get("predecoder") or {}
    hostname = pre.get("hostname") or ""
    if not hostname:
        agent = record.get("agent") or {}
        hostname = agent.get("name") or ""
    return hostname or "unknown-host"


@dataclass
class LoadedRecord:
    """单条 ndjson 记录及其解析出的依赖事件。"""
    record: dict
    events: List[DependencyEvent]
    index: int


def load_ndjson_with_events(path: str) -> List[LoadedRecord]:
    """加载 ndjson 并解析每条记录的依赖事件。"""
    loaded: List[LoadedRecord] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            events = parse_dependency_events_from_line(line)
            loaded.append(LoadedRecord(record=record, events=events, index=i))
    return loaded


def get_context_events(
    loaded: List[LoadedRecord],
    alert_index: int,
    alert_host: str,
    window_lines: int = 500,
) -> List[DependencyEvent]:
    """获取告警上下文内的依赖事件（同 host，前后 window_lines 行）。"""
    start = max(0, alert_index - window_lines)
    end = min(len(loaded), alert_index + window_lines + 1)
    out: List[DependencyEvent] = []
    seen: set = set()
    for i in range(start, end):
        r = loaded[i]
        if _normalize_hostname(r.record) != alert_host:
            continue
        for ev in r.events:
            key = (ev.src.id, ev.dst.id, ev.rel)
            if key not in seen:
                seen.add(key)
                out.append(ev)
    return out


def merge_paths_by_threshold(
    path_scores: List[tuple[List[DependencyEvent], float]],
    tau_m: float,
) -> List[List[DependencyEvent]]:
    """
    Algorithm 3: 按合并阈值 τm 合并高异常分数路径，生成 true alert dependency graph。

    路径按异常分数降序排列，若相邻路径分数差 S1-S2 < τm 则均保留。
    """
    if not path_scores:
        return []
    sorted_ps = sorted(path_scores, key=lambda x: -x[1])
    merged: List[List[DependencyEvent]] = []
    for i, (path, s1) in enumerate(sorted_ps):
        merged.append(path)
        if i + 1 < len(sorted_ps):
            _, s2 = sorted_ps[i + 1]
            if s1 - s2 >= tau_m:
                break
    return merged


@dataclass
class TriageResult:
    """单条告警的 triage 结果。"""
    alert_index: int
    rule_id: str
    rule_desc: str
    host: str
    aggregate_score: float
    path_count: int
    concise_graph_edges: List[tuple[str, str, str]] = field(default_factory=list)


def run_triage_for_alert(
    loaded: List[LoadedRecord],
    alert_index: int,
    db: EventFrequencyDB,
    tau_l: int = 5,
    tau_m: float = 0.1,
    window_lines: int = 500,
) -> Optional[TriageResult]:
    """
    对单条告警执行 NODOZE triage（Algorithm 1 + 路径评分 + Algorithm 3）。
    """
    r = loaded[alert_index]
    if not r.events:
        return None
    alert_event = r.events[0]
    host = _normalize_hostname(r.record)
    rule = r.record.get("rule") or {}
    rule_id = str(rule.get("id", ""))
    rule_desc = rule.get("description", "")

    context = get_context_events(loaded, alert_index, host, window_lines)
    if not context:
        context = r.events

    paths = get_path_anomaly_scores(alert_event, context, tau_l)
    if not paths:
        return TriageResult(
            alert_index=alert_index,
            rule_id=rule_id,
            rule_desc=rule_desc,
            host=host,
            aggregate_score=1.0,
            path_count=0,
        )

    in_scores, out_scores = compute_in_out_scores_for_graph(context)
    path_scores: List[tuple[List[DependencyEvent], float]] = []
    for p in paths:
        ps = score_path(db, p, in_scores, out_scores)
        path_scores.append((p, ps.anomaly_score))

    merged = merge_paths_by_threshold(path_scores, tau_m)
    aggregate = max((s for _, s in path_scores), default=0.0)

    edges: List[tuple[str, str, str]] = []
    for path in merged:
        for ev in path:
            edges.append((ev.src.id, ev.dst.id, ev.rel))

    return TriageResult(
        alert_index=alert_index,
        rule_id=rule_id,
        rule_desc=rule_desc,
        host=host,
        aggregate_score=aggregate,
        path_count=len(paths),
        concise_graph_edges=edges,
    )


def run_triage(
    ndjson_path: str,
    db_path: str,
    tau_l: int = 5,
    tau_m: float = 0.1,
    tau_d: Optional[float] = None,
    window_lines: int = 500,
) -> List[TriageResult]:
    """
    对 ndjson 中所有攻击相关告警执行 triage，按异常分数排序。
    """
    loaded = load_ndjson_with_events(ndjson_path)
    alert_indices = [
        i for i, r in enumerate(loaded)
        if is_alert_record(r.record) and r.events
    ]

    db = EventFrequencyDB(db_path)
    results: List[TriageResult] = []
    try:
        for idx in alert_indices:
            res = run_triage_for_alert(loaded, idx, db, tau_l, tau_m, window_lines)
            if res:
                results.append(res)
    finally:
        db.close()

    results.sort(key=lambda x: -x.aggregate_score)
    if tau_d is not None:
        results = [r for r in results if r.aggregate_score >= tau_d]
    return results


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="NODOZE 告警 Triage：按异常分数排序攻击相关告警"
    )
    parser.add_argument(
        "--ndjson",
        default=cfg.get("triage_ndjson_path"),
        help="待检测日志 ndjson 路径（可从 config.json 的 triage_ndjson_path 读取）",
    )
    parser.add_argument(
        "--db",
        default=cfg.get("db_path", "event_freq.db"),
        help="Event Frequency 数据库路径（可从 config.json 读取）",
    )
    parser.add_argument(
        "--tau-l",
        type=int,
        default=cfg.get("tau_l", 5),
        help="最大路径长度 τl（可从 config.json 读取）",
    )
    parser.add_argument(
        "--tau-m",
        type=float,
        default=cfg.get("tau_m", 0.1),
        help="路径合并阈值 τm（可从 config.json 读取）",
    )
    parser.add_argument(
        "--tau-d",
        type=float,
        default=cfg.get("tau_d"),
        help="决策阈值 τd（可从 config.json 读取，低于此分数的告警视为误报）",
    )
    parser.add_argument(
        "-n",
        type=int,
        default=cfg.get("top_n"),
        help="仅输出前 N 条告警（可从 config.json 读取）",
    )
    parser.add_argument(
        "--window-lines",
        type=int,
        default=cfg.get("window_lines", 500),
        help="上下文窗口行数（可从 config.json 读取）",
    )
    args = parser.parse_args()

    if not args.ndjson:
        parser.error("请指定 --ndjson，或在 config.json 中设置 triage_ndjson_path")
    if not Path(args.db).exists():
        print(f"错误: 频率数据库不存在: {args.db}")
        print("请先运行: python freq_db.py（或检查 config.json 中的 baseline_ndjson_path、db_path）")
        return

    results = run_triage(
        args.ndjson, args.db, args.tau_l, args.tau_m, args.tau_d, args.window_lines
    )
    if args.n:
        results = results[: args.n]

    print(f"共 {len(results)} 条攻击相关告警，按异常分数排序：\n")
    for i, r in enumerate(results, 1):
        print(f"[{i}] rule_id={r.rule_id} host={r.host} score={r.aggregate_score:.4f}")
        print(f"    {r.rule_desc}")
        print()


if __name__ == "__main__":
    main()


__all__ = [
    "ALERT_RULE_IDS",
    "is_alert_record",
    "load_ndjson_with_events",
    "get_context_events",
    "merge_paths_by_threshold",
    "run_triage",
    "run_triage_for_alert",
    "TriageResult",
]
