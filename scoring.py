"""异常打分与路径评分模块（对应论文 §VI, §VII-A）。

实现：
- 从 Event Frequency DB 查询 Freq(E), Freq_src_rel(E)
- Eq.(1) 计算事件转移概率 M_e
- Eq.(2)(3)/(6) 计算路径正则性 RS(P) 与异常分数 AS(P)
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from typing import Iterable, List, Tuple

from events import DependencyEvent


@dataclass
class PathScore:
    """单条依赖路径的评分结果。"""

    events: List[DependencyEvent]
    regularity_score: float
    anomaly_score: float


class EventFrequencyDB:
    """封装对 SQLite 事件频率数据库的查询（对应论文 §VII-A）。"""

    def __init__(self, sqlite_path: str) -> None:
        self._conn = sqlite3.connect(sqlite_path)
        self._conn.row_factory = sqlite3.Row

    def close(self) -> None:
        self._conn.close()

    def get_freq_event(self, src: str, dst: str, rel: str) -> int:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT count FROM event_freq WHERE src=? AND dst=? AND rel=?",
            (src, dst, rel),
        )
        row = cur.fetchone()
        return int(row["count"]) if row else 0

    def get_freq_src_rel(self, src: str, rel: str) -> int:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT count FROM event_freq_src_rel WHERE src=? AND rel=?",
            (src, rel),
        )
        row = cur.fetchone()
        return int(row["count"]) if row else 0


def transition_probability(db: EventFrequencyDB, ev: DependencyEvent) -> float:
    """根据 Eq.(1) 计算事件转移概率 M_e。"""
    f_event = db.get_freq_event(ev.src.id, ev.dst.id, ev.rel)
    f_sr = db.get_freq_src_rel(ev.src.id, ev.rel)
    if f_sr <= 0:
        return 0.0
    return f_event / float(f_sr)


def compute_in_out_scores_for_graph(
    events: Iterable[DependencyEvent],
) -> Tuple[dict[str, float], dict[str, float]]:
    """简化版 IN/OUT 分数（对应 §VI-C 思想）。"""
    out_deg: dict[str, int] = {}
    in_deg: dict[str, int] = {}

    ev_list = list(events)
    for ev in ev_list:
        out_deg[ev.src.id] = out_deg.get(ev.src.id, 0) + 1
        in_deg[ev.dst.id] = in_deg.get(ev.dst.id, 0) + 1

    in_score: dict[str, float] = {}
    out_score: dict[str, float] = {}

    for node, deg in out_deg.items():
        out_score[node] = 1.0 / (1.0 + deg)
    for node, deg in in_deg.items():
        in_score[node] = 1.0 / (1.0 + deg)

    for node in out_deg:
        if node not in in_score:
            in_score[node] = 1.0
    for node in in_deg:
        if node not in out_score:
            out_score[node] = 1.0

    return in_score, out_score


def score_path(
    db: EventFrequencyDB,
    path_events: List[DependencyEvent],
    in_scores: dict[str, float],
    out_scores: dict[str, float],
    decay_alpha: float | None = None,
) -> PathScore:
    """根据 Eq.(2)(3)/(6) 计算单条路径的 RS(P) 与 AS(P)。"""
    if not path_events:
        return PathScore(events=[], regularity_score=0.0, anomaly_score=1.0)

    rs_log = 0.0
    for ev in path_events:
        m_e = transition_probability(db, ev)
        in_v = in_scores.get(ev.src.id, 1.0)
        out_v = out_scores.get(ev.dst.id, 1.0)

        term = in_v * m_e * out_v
        if decay_alpha is not None:
            term *= decay_alpha

        if term <= 0:
            rs_log = float("-inf")
            break
        rs_log += math.log(term)

    if rs_log == float("-inf"):
        rs = 0.0
    else:
        rs = math.exp(rs_log)

    ascore = 1.0 - rs
    if ascore < 0.0:
        ascore = 0.0
    elif ascore > 1.0:
        ascore = 1.0

    return PathScore(events=list(path_events), regularity_score=rs, anomaly_score=ascore)


__all__ = [
    "EventFrequencyDB",
    "transition_probability",
    "compute_in_out_scores_for_graph",
    "score_path",
    "PathScore",
]

