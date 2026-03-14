"""
NODOZE 依赖图构建与路径枚举（对应论文 §V, Algorithm 1）。

实现：
- 从依赖事件集合构建有向图 G
- DFS 后向遍历（ancestry）与前向遍历（progeny）
- 路径组合 COMBINEPATHS(Lb, Lf)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from events import DependencyEvent


def build_dependency_graph(events: List[DependencyEvent]) -> Tuple[
    Dict[str, List[Tuple[DependencyEvent, str]]],  # backward: dst -> [(edge, src)]
    Dict[str, List[Tuple[DependencyEvent, str]]],  # forward: src -> [(edge, dst)]
]:
    """
    从依赖事件列表构建图的邻接结构（对应 GETDEPENDENCYGRAPH）。

    返回:
        backward_adj: 对于顶点 v，列出所有 (edge, u) 其中 edge.dst.id==v, edge.src.id==u
        forward_adj:  对于顶点 v，列出所有 (edge, w) 其中 edge.src.id==v, edge.dst.id==w
    """
    backward_adj: Dict[str, List[Tuple[DependencyEvent, str]]] = defaultdict(list)
    forward_adj: Dict[str, List[Tuple[DependencyEvent, str]]] = defaultdict(list)

    for ev in events:
        backward_adj[ev.dst.id].append((ev, ev.src.id))
        forward_adj[ev.src.id].append((ev, ev.dst.id))

    return dict(backward_adj), dict(forward_adj)


def dfs_traversal_backward(
    backward_adj: Dict[str, List[Tuple[DependencyEvent, str]]],
    start_vertex: str,
    tau_l: int,
) -> List[List[DependencyEvent]]:
    """
    从 start_vertex 向后（沿入边）DFS，生成长度不超过 tau_l 的路径（Algorithm 1 Line 4）。

    路径为边的序列：第一条边指向 start，后续边沿反向延伸至祖先。
    """
    if tau_l <= 0:
        return [[]]

    paths: List[List[DependencyEvent]] = [[]]

    def dfs(v: str, depth: int, path: List[DependencyEvent], seen: Set[str]) -> None:
        if depth >= tau_l:
            return
        for ev, u in backward_adj.get(v, []):
            if u in seen:
                continue
            new_path = path + [ev]
            paths.append(new_path.copy())
            dfs(u, depth + 1, new_path, seen | {u})

    dfs(start_vertex, 0, [], {start_vertex})
    return paths


def dfs_traversal_forward(
    forward_adj: Dict[str, List[Tuple[DependencyEvent, str]]],
    start_vertex: str,
    tau_l: int,
) -> List[List[DependencyEvent]]:
    """
    从 start_vertex 向前（沿出边）DFS，生成长度不超过 tau_l 的路径（Algorithm 1 Line 5）。
    """
    if tau_l <= 0:
        return [[]]

    paths: List[List[DependencyEvent]] = [[]]

    def dfs(v: str, depth: int, path: List[DependencyEvent], seen: Set[str]) -> None:
        if depth >= tau_l:
            return
        for ev, w in forward_adj.get(v, []):
            if w in seen:
                continue
            new_path = path + [ev]
            paths.append(new_path.copy())
            dfs(w, depth + 1, new_path, seen | {w})

    dfs(start_vertex, 0, [], {start_vertex})
    return paths


def combine_paths(
    alert_event: DependencyEvent,
    backward_paths: List[List[DependencyEvent]],
    forward_paths: List[List[DependencyEvent]],
    tau_l: int,
) -> List[List[DependencyEvent]]:
    """
    组合后向与前向路径，生成包含告警边的完整路径（Algorithm 1 Line 6）。

    完整路径 P = [B_{k}, ..., B_1, E_α, F_1, ..., F_m]，长度 <= τl。
    """
    combined: List[List[DependencyEvent]] = []
    for bp in backward_paths:
        for fp in forward_paths:
            total_len = len(bp) + 1 + len(fp)
            if total_len > tau_l:
                continue
            # 后向路径需反转（从祖先到告警）
            rev_bp = list(reversed(bp))
            p = rev_bp + [alert_event] + fp
            combined.append(p)
    if not combined:
        combined.append([alert_event])
    return combined


def get_path_anomaly_scores(
    alert_event: DependencyEvent,
    events: List[DependencyEvent],
    tau_l: int,
) -> List[List[DependencyEvent]]:
    """
    Algorithm 1: GETPATHANOMALYSCORE 的路径枚举部分。

    输入: 告警事件 E_α, 图内所有事件 events, 最大路径长度 τl
    输出: 依赖路径列表 Lp（评分由 scoring 模块完成）
    """
    backward_adj, forward_adj = build_dependency_graph(events)
    vsrc = alert_event.src.id
    vdst = alert_event.dst.id

    lb = dfs_traversal_backward(backward_adj, vsrc, tau_l - 1)
    lf = dfs_traversal_forward(forward_adj, vdst, tau_l - 1)

    lp = combine_paths(alert_event, lb, lf, tau_l)
    return lp


__all__ = [
    "build_dependency_graph",
    "dfs_traversal_backward",
    "dfs_traversal_forward",
    "combine_paths",
    "get_path_anomaly_scores",
]
