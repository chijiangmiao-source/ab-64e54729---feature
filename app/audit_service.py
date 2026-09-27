"""约束一致性审计编排。

审计只能引用已保存且验签通过的单包复核记录；约束取自这些记录被签名的
原始载荷字节（直接从落库的原始报文重新严格解析抽取，绝不信任请求方提交
的任何内容）。任何输入缺陷都在落库审计编号之前抛出 AuditRejected。
"""

from __future__ import annotations

import json

from cbor_strict import CBORError, Tagged, decode
from rationals import RationalError, parse_rational
import audit_engine


class AuditRejected(Exception):
    """审计输入不合法：不生成审计编号。errors 为逐项原因。"""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("；".join(errors))


def _payload_object(package_hex: str) -> dict:
    """从已保存的原始 COSE_Sign1 报文字节中重新抽取 JSON 载荷对象。"""
    package = bytes.fromhex(package_hex)
    top = decode(package)
    if isinstance(top, Tagged):
        top = top.value
    payload_raw = top[2]
    return json.loads(payload_raw.decode("utf-8"))


def build_audit(db, review_ids) -> dict:
    """校验引用并执行审计，返回待持久化的结果字典（尚无审计编号）。"""
    errors: list[str] = []

    if not isinstance(review_ids, list) or not review_ids:
        raise AuditRejected(["review_ids 必须是非空数组"])
    if not all(isinstance(x, str) and x for x in review_ids):
        raise AuditRejected(["复核编号必须为非空字符串"])

    # 重复引用直接拒绝，不生成审计
    if len(set(review_ids)) != len(review_ids):
        dup = sorted({x for x in review_ids if review_ids.count(x) > 1})
        raise AuditRejected([f"复核编号重复引用：{', '.join(dup)}"])

    detector = None
    staged = []          # (source_id, index, left, right, Fraction)
    source_info = []     # 来源展示信息（按首次出现顺序）
    seen_sources = set()

    for rid in review_ids:
        row = db.get_review_row(rid)
        if row is None:
            errors.append(f"无通过记录的编号：{rid}（或记录不存在）")
            continue
        result = row["result"]
        if result.get("verdict") != "pass":
            errors.append(f"复核编号 {rid} 未通过验签，不得作为审计来源")
            continue

        try:
            payload = _payload_object(row["package_hex"])
        except (CBORError, ValueError, KeyError, IndexError, TypeError) as exc:
            errors.append(f"复核编号 {rid} 的已保存报文无法重新抽取原始载荷：{exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"复核编号 {rid} 的载荷不是 JSON 对象")
            continue

        if "detector_id" not in payload:
            errors.append(f"复核编号 {rid} 的载荷缺少 detector_id 字段")
            continue
        if "constraints" not in payload:
            errors.append(f"复核编号 {rid} 的载荷缺少 constraints 字段")
            continue
        det = payload["detector_id"]
        if not isinstance(det, str) or not det:
            errors.append(f"复核编号 {rid} 的 detector_id 必须是非空字符串")
            continue
        constraints = payload["constraints"]
        if not isinstance(constraints, list):
            errors.append(f"复核编号 {rid} 的 constraints 必须是数组")
            continue

        if detector is None:
            detector = det
        elif det != detector:
            errors.append(
                f"探测器不一致：{rid} 声明 {det!r}，此前来源为 {detector!r}"
            )
            continue

        parsed_here = []
        for index, item in enumerate(constraints):
            where = f"复核编号 {rid} constraints[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{where} 必须是 JSON 对象")
                continue
            missing = [k for k in ("left", "right", "bound") if k not in item]
            if missing:
                errors.append(f"{where} 缺少字段：{', '.join(missing)}")
                continue
            left, right, bound_text = item["left"], item["right"], item["bound"]
            if not isinstance(left, str) or not left:
                errors.append(f"{where} 的 left 必须是非空参数标识字符串")
                left = None
            if not isinstance(right, str) or not right:
                errors.append(f"{where} 的 right 必须是非空参数标识字符串")
                right = None
            try:
                bound = parse_rational(bound_text)
            except RationalError as exc:
                errors.append(f"{where} {exc}")
                bound = None
            # 只有三元组全部合法才入图；任一非法最终都会因 errors 非空而拒绝
            if left is not None and right is not None and bound is not None:
                parsed_here.append((rid, index, left, right, bound))

        staged.extend(parsed_here)
        if rid not in seen_sources:
            seen_sources.add(rid)
            source_info.append({
                "review_id": rid,
                "payload_sha256": result.get("payload_sha256"),
                "constraint_count": len(constraints),
            })

    if errors:
        raise AuditRejected(errors)

    outcome = audit_engine.analyze(staged)
    # 来源取全部通过校验的引用（含仅含空 constraints 者），按复核编号稳定排列
    sources = sorted(source_info, key=lambda s: s["review_id"])

    return {
        "detector_id": detector,
        "review_ids": list(review_ids),
        "constraint_count": len(staged),
        "verdict": outcome["verdict"],
        "sources": sources,
        "constraints": outcome["constraints"],
        "params": outcome["params"],
        "assignment": outcome["assignment"],
        "checks": outcome["checks"],
        "minimal_contradictions": outcome["minimal_contradictions"],
        **({"negative_cycle_evidence": outcome["negative_cycle_evidence"]}
           if outcome["verdict"] == "infeasible" else {}),
    }
