"""约束一致性审计引擎。

审查员从已通过（验签成功）的单包复核记录中选择若干编号，服务取出这些
记录保存的 *原始* 载荷，校验它们均为含相同 ``detector_id`` 与
``constraints`` 数组的 JSON 对象，然后以任意精度有理数（Fraction）
建立差分约束图：

    约束项 {"left": a, "right": b, "bound": c}  表示  a - b <= c

- 可行：Bellman-Ford 求一组满足赋值（按参数标识稳定排列），并对每条
  约束做精确复算；
- 不可行：取出一个负环作为矛盾证据，再以指数级分支定界（按来源复核
  编号、数组位置排序的二元决策 DFS + 迭代加深）精确裁决最少删除集；
  同尺寸的不同删除集按 (来源编号, 数组位置) 字典序稳定选择。
"""

from __future__ import annotations

import json
from fractions import Fraction

from cbor_strict import Tagged, decode
from rationals import RationalError, format_rational, parse_canonical

BOUND_FIELDS = ("left", "right", "bound")


class AuditReject(ValueError):
    """审计请求非法：拒绝且不生成审计记录。"""


# ---------------------------------------------------------------- 载荷提取


def _payload_object(package_hex: str) -> dict:
    """从已保存报文的原始字节中取出载荷 JSON 对象（不重新编码任何内容）。"""
    top = decode(bytes.fromhex(package_hex))
    if isinstance(top, Tagged):
        top = top.value
    payload_raw = top[2]
    return json.loads(payload_raw.decode("utf-8"))


def collect_constraints(review_rows: list[dict], verify) -> tuple[str, list[dict]]:
    """根据已保存复核记录构造带来源的约束序列。

    review_rows 已按编号排序去重；verify 为 cose.verify_review，用于再次
    确认每条保存记录确实验签通过。任何结构问题抛 AuditReject。
    """
    detector_id = None
    constraints: list[dict] = []

    for row in review_rows:
        rid = row["id"]
        result = verify(row["public_key_hex"], row["package_hex"])
        if result.get("verdict") != "pass":
            raise AuditReject(f"复核编号 {rid} 不是验签通过记录，不得引用")
        try:
            obj = _payload_object(row["package_hex"])
        except Exception as exc:  # 通过记录理论上不会发生
            raise AuditReject(f"复核编号 {rid} 的保存载荷无法解析：{exc}") from exc

        if not isinstance(obj, dict):
            raise AuditReject(f"复核编号 {rid} 的载荷不是 JSON 对象")
        if "detector_id" not in obj:
            raise AuditReject(f"复核编号 {rid} 的载荷缺少 detector_id 字段")
        if "constraints" not in obj:
            raise AuditReject(f"复核编号 {rid} 的载荷缺少 constraints 字段")

        payload_detector = obj["detector_id"]
        if not isinstance(payload_detector, str) or not payload_detector:
            raise AuditReject(f"复核编号 {rid} 的 detector_id 必须是非空字符串")
        if detector_id is None:
            detector_id = payload_detector
        elif payload_detector != detector_id:
            raise AuditReject(
                f"探测器不一致：{detector_id!r} 与编号 {rid} 的 "
                f"{payload_detector!r} 不符"
            )

        items = obj["constraints"]
        if not isinstance(items, list):
            raise AuditReject(f"复核编号 {rid} 的 constraints 必须是数组")
        for position, item in enumerate(items):
            if not isinstance(item, dict):
                raise AuditReject(
                    f"编号 {rid} constraints[{position}] 不是 JSON 对象"
                )
            missing = [f for f in BOUND_FIELDS if f not in item]
            if missing:
                raise AuditReject(
                    f"编号 {rid} constraints[{position}] 缺少字段："
                    + "、".join(missing)
                )
            left, right, bound_text = (item[f] for f in BOUND_FIELDS)
            if not isinstance(left, str) or not left:
                raise AuditReject(
                    f"编号 {rid} constraints[{position}].left 必须是非空字符串"
                )
            if not isinstance(right, str) or not right:
                raise AuditReject(
                    f"编号 {rid} constraints[{position}].right 必须是非空字符串"
                )
            try:
                bound = parse_canonical(bound_text)
            except RationalError as exc:
                raise AuditReject(
                    f"编号 {rid} constraints[{position}].bound 非法：{exc}"
                ) from exc
            constraints.append({
                "source_id": rid,
                "position": position,
                "left": left,
                "right": right,
                "bound": bound,
                "bound_text": bound_text,
            })

    if not constraints:
        raise AuditReject("全部载荷的 constraints 数组均为空，无约束可审计")
    return detector_id, constraints


# ---------------------------------------------------------------- 差分约束图


def _bellman_ford(edges, nodes):
    """以超源 0 初始化做 Bellman-Ford。

    edges: [(u, v, weight, edge_index)]，表示 v - u <= weight。
    返回 (dist, pred)；pred[v] = (u, edge_index)。
    """
    dist = {node: Fraction(0) for node in nodes}
    pred = {}
    for _ in range(len(nodes) - 1):
        changed = False
        for u, v, w, idx in edges:
            candidate = dist[u] + w
            if candidate < dist[v]:
                dist[v] = candidate
                pred[v] = (u, idx)
                changed = True
        if not changed:
            break
    return dist, pred


def _relaxable_edge(edges, dist):
    for u, v, w, idx in edges:
        if dist[u] + w < dist[v]:
            return idx
    return None


def _negative_cycle(edges, nodes):
    """返回负环上的边索引序列（无负环返回 None）。"""
    dist, pred = _bellman_ford(edges, nodes)
    start_idx = _relaxable_edge(edges, dist)
    if start_idx is None:
        return None
    # 再松弛一轮并沿前驱链回溯，保证落到环上。
    for u, v, w, idx in edges:
        if dist[u] + w < dist[v]:
            pred[v] = (u, idx)
    node = edges[start_idx][1]
    for _ in range(len(nodes)):
        node = pred[node][0]
    cycle_nodes = [node]
    cycle_edges = []
    cur = node
    while True:
        prev, idx = pred[cur]
        cycle_edges.append(idx)
        cur = prev
        if cur == node:
            break
        cycle_nodes.append(cur)
    cycle_edges.reverse()
    return cycle_edges


def _is_feasible(edges, nodes):
    if not edges:
        return True
    dist, _ = _bellman_ford(edges, nodes)
    return _relaxable_edge(edges, dist) is None


def _minimum_removed(edges, nodes):
    """迭代加深 + 按索引序“先删除后保留”的 DFS，求最少删除集。

    两个同为最小尺寸的候选集，从首个分歧的边索引看，删除该边的候选集
    其排序元组首位更小，因此先展开“删除”分支得到的就是按
    (来源编号, 数组位置) 字典序最小的删除集。负环中若已没有尚未决策的
    边，则当前分支无解，直接剪枝。
    """
    n = len(edges)
    result = None

    def dfs(i, removed):
        nonlocal result
        if result is not None:
            return
        removed_set = set(removed)
        # 未决策边（索引 >= i）一律先按保留构造当前视图。
        view = [e for j, e in enumerate(edges)
                if j >= i or j not in removed_set]
        if _is_feasible(view, nodes):
            result = list(removed)
            return
        if i == n or len(removed) >= dfs.limit:
            return
        cycle = _negative_cycle(view, nodes)
        if cycle is not None and all(idx < i for idx in cycle):
            return  # 负环只含已决定保留的边，无法再打破
        # 先尝试删除第 i 条，再尝试保留（删除集字典序决胜）。
        dfs(i + 1, removed + [i])
        if result is None:
            dfs(i + 1, removed)

    for limit in range(n + 1):
        dfs.limit = limit
        dfs(0, [])
        if result is not None:
            return result
    return list(range(n))  # 理论不可达


# ---------------------------------------------------------------- 审计主流程


def _constraint_view(c: dict, index: int) -> dict:
    return {
        "index": index,
        "source_id": c["source_id"],
        "position": c["position"],
        "left": c["left"],
        "right": c["right"],
        "bound": c["bound_text"],
    }


def _assignment(dist: dict) -> dict:
    """按参数标识（码位序）稳定排列的满足赋值。"""
    return {node: format_rational(dist[node]) for node in sorted(dist)}


def _checks(constraints, kept_mask, dist):
    """对保留约束做逐约束精确复算。"""
    out = []
    for i, c in enumerate(constraints):
        if not kept_mask[i]:
            continue
        diff = dist[c["left"]] - dist[c["right"]]
        out.append({
            "index": i,
            "source_id": c["source_id"],
            "position": c["position"],
            "left": c["left"],
            "right": c["right"],
            "bound": c["bound_text"],
            "difference": format_rational(diff),
            "slack": format_rational(c["bound"] - diff),
            "satisfied": diff <= c["bound"],
        })
    return out


def run_audit(detector_id: str, constraints: list[dict]) -> dict:
    """约束已收集并校验，执行可行性裁决。"""
    # 按 (来源编号, 数组位置) 稳定排序，边索引即决胜顺序。
    constraints = sorted(constraints, key=lambda c: (c["source_id"], c["position"]))
    nodes = sorted({c["left"] for c in constraints}
                   | {c["right"] for c in constraints})
    # left - right <= bound  ⇔  dist[left] <= dist[right] + bound
    # 故有向边 right -> left，权重为 bound（Bellman-Ford 求最短路不动点）。
    edges = [(c["right"], c["left"], c["bound"], i)
             for i, c in enumerate(constraints)]

    base = {
        "kind": "constraint_audit",
        "detector_id": detector_id,
        "constraint_count": len(constraints),
        "constraints": [_constraint_view(c, i) for i, c in enumerate(constraints)],
    }

    cycle = _negative_cycle(edges, nodes)
    if cycle is None:
        dist, _ = _bellman_ford(edges, nodes)
        base.update({
            "status": "feasible",
            "assignment": _assignment(dist),
            "checks": _checks(constraints, [True] * len(constraints), dist),
        })
        return base

    # 不可行：负环证据 -> 精确最少删除裁决。
    cycle_view = [_constraint_view(constraints[i], i) for i in cycle]
    removed = _minimum_removed(edges, nodes)
    kept_mask = [i not in set(removed) for i in range(len(constraints))]
    surviving = [e for e in edges if kept_mask[e[3]]]
    dist, _ = _bellman_ford(surviving, nodes)

    base.update({
        "status": "infeasible",
        "negative_cycle": {
            "constraints": cycle_view,
            "note": "沿环各有向边权重之和为负，任何赋值都无法同时满足",
        },
        "minimum_deletions": {
            "count": len(removed),
            "tie_break": "同尺寸按来源复核编号、再按数组位置字典序稳定选择",
            "constraints": [_constraint_view(constraints[i], i) for i in removed],
        },
        "assignment_after_deletions": _assignment(dist),
        "checks_after_deletions": _checks(constraints, kept_mask, dist),
    })
    return base
