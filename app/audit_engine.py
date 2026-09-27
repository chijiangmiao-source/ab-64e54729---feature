"""差分约束图与约束一致性审计引擎（全部使用任意精度有理数 Fraction）。

每条约束声明两个参数之间的上界：``left - right <= bound``。
图中以有向边 ``right -> left``、权 ``bound`` 表示；全部约束同时成立
当且仅当图中不存在总权严格为负的环（负环）。

- 可行性：Bellman-Ford 超源松弛判定负环，并由最短距离得到一组满足赋值；
- 不可行裁决：自负环证据出发，冲突驱动地枚举命中（删除后即恢复可行的）
  约束集合，在命中内求权最小者，再按 (来源复核编号, 数组位置) 的稳定
  字典序择优，给出精确的最少删除矛盾集。
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from rationals import format_rational


@dataclass(frozen=True)
class Constraint:
    """一条解析后的约束：left - right <= bound。

    order 是该约束在本次审计全部引用中的稳定次序（先按来源编号排序、
    再按在来源 constraints 数组中的位置），用于稳定选择。
    """

    source_id: str
    index: int
    order: int
    left: str
    right: str
    bound: Fraction


def _edges(constraints):
    """约束 -> 有向边列表；边 right->left 权 bound；自环直接显式列出。"""
    edges = []
    for c in constraints:
        edges.append((c.right, c.left, c.bound, c.order))
    return edges


def _bellman_ford(nodes, edges):
    """超源（到每点距离 0）Bellman-Ford。

    返回 (dist, predecessor)：算法结束后仍可松弛即存在负环。
    同轮内按目标参数、来源次序稳定松弛，保证裁决可复现。
    pred[v] = (u, order)：v 的最短前驱边及其约束序号。
    """
    dist = {v: Fraction(0) for v in nodes}
    pred = {v: None for v in nodes}
    n = len(nodes)
    for _ in range(n):
        changed = False
        for u, v, w, order in edges:
            cand = dist[u] + w
            if cand < dist[v]:
                dist[v] = cand
                pred[v] = (u, order)
                changed = True
        if not changed:
            break
    return dist, pred


def _negative_cycle(nodes, edges):
    """存在负环时返回环上约束的 order 集合，否则返回 None。"""
    dist, pred = _bellman_ford(nodes, edges)
    relaxed_order = None
    hit_v = None
    for u, v, w, order in edges:
        if dist[u] + w < dist[v]:
            relaxed_order = order
            hit_v = v
            break
    if hit_v is None:
        return None
    # 沿前驱链回溯：|V| 步后必然落在某个负环上
    cur = hit_v
    for _ in range(len(nodes)):
        p = pred[cur]
        if p is None:
            break
        cur = p[0]
    cycle_orders = set()
    start = cur
    while True:
        p = pred[cur]
        if p is None:
            break
        u, order = p
        cycle_orders.add(order)
        cur = u
        if cur == start:
            break
    # 理论上不会走到（松弛边证明负环存在）；保险起见把该边计入冲突
    if not cycle_orders:
        cycle_orders = {relaxed_order}
    return cycle_orders


def feasible(constraints, nodes):
    """约束系统是否可行（不存在负环）。"""
    return _negative_cycle(nodes, _edges(constraints)) is None


def _minimum_hitting_set(constraints, nodes):
    """求最少删除的约束 order 集合。

    以负环作为必须命中的冲突集合，冲突驱动地枚举最小命中集：
    - 命中集 = 删除后系统恢复可行的约束集；
    - 在最小基数命中集之间，按 order 的稳定字典序（order 越小对应的
      来源编号/数组位置越早）择优。
    """
    edges_all = _edges(constraints)

    def is_hitting(chosen):
        edges = [e for e in edges_all if e[3] not in chosen]
        return _negative_cycle(nodes, edges) is None

    best = None  # frozenset(orders)

    def key(chosen):
        return tuple(sorted(chosen))

    def search(chosen, blocked):
        """chosen：已删除约束；blocked：本分支永久不得再选的约束。

        在冲突 C={c1<c2<...} 上分 k 支：第 i 支加入 ci 并永久排除
        c1..c(i-1)。任意命中集 H 取其中下标最小的 ci ∈ H，则
        c1..c(i-1) 均不在 H，H 恰在第 i 支中被枚举一次，保证完备且无重复。
        """
        nonlocal best
        if best is not None and len(chosen) > len(best):
            return
        if is_hitting(chosen):
            if best is None or len(chosen) < len(best) or (
                len(chosen) == len(best) and key(chosen) < key(best)
            ):
                best = frozenset(chosen)
            return
        conflict = _negative_cycle(nodes, [e for e in edges_all if e[3] not in chosen])
        if conflict is None:  # 保险：理论上 is_hitting 已覆盖
            search(chosen, blocked)
            return
        candidates = sorted(o for o in conflict if o not in blocked)
        if not candidates:
            return  # 冲突环已全部被本分支排除：此支不存在可行命中集
        newly_blocked = set()
        for o in candidates:
            new_chosen = chosen | {o}
            if best is not None and len(new_chosen) > len(best):
                # o 递增：后续分支只会更长，全部可剪
                break
            search(new_chosen, blocked | newly_blocked)
            newly_blocked.add(o)

    search(frozenset(), frozenset())
    return set(best) if best is not None else set()


def analyze(staged):
    """对暂存的约束执行审计。

    staged: [(source_id, index, left, right, bound:Fraction), ...]，
    调用方已保证引用唯一、detector 一致、字段与有理数合法。
    返回可 JSON 序列化的审计结论字典。
    """
    # 稳定次序：先来源编号、再数组位置（staged 本身已按此排好序，显式排序以防调用方疏忽）
    staged = sorted(staged, key=lambda t: (t[0], t[1]))
    constraints = [
        Constraint(source_id=sid, index=idx, order=i, left=l, right=r, bound=b)
        for i, (sid, idx, l, r, b) in enumerate(staged)
    ]
    nodes = sorted({c.left for c in constraints} | {c.right for c in constraints})
    edges = _edges(constraints)

    cycle = _negative_cycle(nodes, edges)
    sources = []
    seen_sources = set()
    for c in constraints:
        if c.source_id not in seen_sources:
            seen_sources.add(c.source_id)
            sources.append(c.source_id)

    constraint_reports = [
        {
            "source_review_id": c.source_id,
            "index": c.index,
            "left": c.left,
            "right": c.right,
            "bound": format_rational(c.bound),
        }
        for c in constraints
    ]

    if cycle is None:
        dist, _pred = _bellman_ford(nodes, edges)
        # 超源距离给出一组满足赋值；按参数标识稳定排列
        assignment = [
            {"param": v, "value": format_rational(dist[v])} for v in nodes
        ]
        # 逐约束复算：left - right 与上界比较
        checks = []
        for c in constraints:
            lhs = dist[c.left] - dist[c.right]
            checks.append({
                "source_review_id": c.source_id,
                "index": c.index,
                "left": c.left,
                "right": c.right,
                "bound": format_rational(c.bound),
                "left_minus_right": format_rational(lhs),
                "slack": format_rational(c.bound - lhs),
                "holds": lhs <= c.bound,
            })
        return {
            "verdict": "feasible",
            "sources": sources,
            "constraints": constraint_reports,
            "params": nodes,
            "assignment": assignment,
            "checks": checks,
            "minimal_contradictions": [],
        }

    remove_orders = _minimum_hitting_set(constraints, nodes)
    removed = sorted(remove_orders)
    contradictions = [
        {
            "source_review_id": constraints[o].source_id,
            "index": constraints[o].index,
            "left": constraints[o].left,
            "right": constraints[o].right,
            "bound": format_rational(constraints[o].bound),
        }
        for o in removed
    ]
    return {
        "verdict": "infeasible",
        "sources": sources,
        "constraints": constraint_reports,
        "params": nodes,
        "assignment": None,
        "checks": None,
        "minimal_contradictions": contradictions,
        "negative_cycle_evidence": [
            {
                "source_review_id": constraints[o].source_id,
                "index": constraints[o].index,
            }
            for o in sorted(cycle)
        ],
    }
