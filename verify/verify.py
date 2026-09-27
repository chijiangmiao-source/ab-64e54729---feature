#!/usr/bin/env python3
"""Compose verify 服务：

1. 单元测试 —— 原始字节验签、非规范/篡改编码拒绝；
2. 构建检查 —— 应用代码字节码编译与模块导入；
3. HTTP 冒烟 —— 健康检查、提交/读取复核记录、拒绝记录可观察。

全部结束后以 0（全部通过）或 1（存在失败）退出，并打印退出码。
"""

import compileall
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.normpath(os.path.join(HERE, "..", "app"))
sys.path.insert(0, APP_DIR)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import audit
import cose
from rationals import RationalError, parse_canonical

PASSES = []
FAILURES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print(f"  [PASS] {name}", flush=True)
    else:
        FAILURES.append((name, detail))
        print(f"  [FAIL] {name}  {detail}", flush=True)


def bstr(b):
    return cose.bstr_header(len(b)) + b


def make_key():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk.hex()


def assemble(protected, payload, sig, unprotected=b"\xa0", tagged=False):
    arr = b"\x84" + bstr(protected) + unprotected + bstr(payload) + bstr(sig)
    return (b"\xd2" + arr) if tagged else arr  # 0xd2 = tag(18) COSE_Sign1


def signed_package(protected, payload, sk, **kw):
    return assemble(protected, payload, sk.sign(cose.sig_structure(protected, payload)), **kw).hex()


def has_reason(result, needle):
    return any(needle in r for r in result["reasons"])


# ---------------------------------------------------------------- 单元测试

def unit_tests():
    print("== 单元测试：原始字节验签与确定性编码拒绝 ==", flush=True)
    sk, pk_hex = make_key()
    protected = b"\xa1\x01\x27"  # {1: -8} => alg = EdDSA
    payload = b'{"device":"ir-cal-01","dose_uGy":4200,"batch":"B7"}'

    r = cose.verify_review(pk_hex, signed_package(protected, payload, sk))
    check("有效报文通过（原始字节验签）",
          r["verdict"] == "pass" and r["signature_valid"] is True and r["reasons"] == [],
          json.dumps(r, ensure_ascii=False))

    r = cose.verify_review(pk_hex, signed_package(protected, payload, sk, tagged=True))
    check("带 tag(18) 的有效报文通过", r["verdict"] == "pass",
          json.dumps(r, ensure_ascii=False))

    # 改动任一载荷字节（不重新签名）必须被拒绝
    mutated = bytearray(payload)
    mutated[mutated.index(b"4")] ^= 0x01
    sig = sk.sign(cose.sig_structure(protected, payload))
    r = cose.verify_review(pk_hex, assemble(protected, bytes(mutated), sig).hex())
    check("改动载荷字节被拒绝", r["verdict"] == "fail" and has_reason(r, "验签失败"),
          json.dumps(r, ensure_ascii=False))

    # 交换为非规范键序的受保护头（签名本身覆盖这些字节，仍须拒绝）
    protected_nc = b"\xa2\x02\x41\x01\x01\x27"  # {2: h'01', 1: -8}，键 2 排在键 1 前
    r = cose.verify_review(pk_hex, signed_package(protected_nc, payload, sk))
    check("非规范键序被拒绝", r["verdict"] == "fail" and has_reason(r, "键序"),
          json.dumps(r, ensure_ascii=False))

    # 非最短整数：alg=-8 编码为 0x38 0x07
    protected_ns = b"\xa1\x01\x38\x07"
    r = cose.verify_review(pk_hex, signed_package(protected_ns, payload, sk))
    check("非最短整数被拒绝", r["verdict"] == "fail" and has_reason(r, "非最短"),
          json.dumps(r, ensure_ascii=False))

    # 顶层数组长度非最短形式：0x98 0x04
    sig = sk.sign(cose.sig_structure(protected, payload))
    body = bstr(protected) + b"\xa0" + bstr(payload) + bstr(sig)
    r = cose.verify_review(pk_hex, (b"\x98\x04" + body).hex())
    check("顶层长度非最短形式被拒绝", r["verdict"] == "fail" and has_reason(r, "非最短"),
          json.dumps(r, ensure_ascii=False))

    # 不定长编码
    r = cose.verify_review(pk_hex, (b"\x9f" + body + b"\xff").hex())
    check("不定长编码被拒绝", r["verdict"] == "fail" and has_reason(r, "不定长"),
          json.dumps(r, ensure_ascii=False))

    # 重复映射键
    protected_dup = b"\xa2\x01\x27\x01\x27"
    r = cose.verify_review(pk_hex, signed_package(protected_dup, payload, sk))
    check("重复映射键被拒绝", r["verdict"] == "fail" and has_reason(r, "重复键"),
          json.dumps(r, ensure_ascii=False))

    # 尾随字节
    r = cose.verify_review(pk_hex, signed_package(protected, payload, sk) + "00")
    check("尾随字节被拒绝", r["verdict"] == "fail" and has_reason(r, "多余字节"),
          json.dumps(r, ensure_ascii=False))

    # 未声明的 COSE 算法：ES256(-7)
    protected_es256 = b"\xa1\x01\x26"
    r = cose.verify_review(pk_hex, signed_package(protected_es256, payload, sk))
    check("非 EdDSA 算法被拒绝", r["verdict"] == "fail" and has_reason(r, "算法"),
          json.dumps(r, ensure_ascii=False))

    # 受保护头未声明 alg
    r = cose.verify_review(pk_hex, signed_package(b"\xa0", payload, sk))
    check("缺少 alg 声明被拒绝", r["verdict"] == "fail" and has_reason(r, "alg"),
          json.dumps(r, ensure_ascii=False))

    # 复用不匹配的签名：用报文 A 的签名配报文 B 的载荷
    other_payload = b'{"device":"ir-cal-02","dose_uGy":1,"batch":"B7"}'
    sig_a = sk.sign(cose.sig_structure(protected, payload))
    r = cose.verify_review(pk_hex, assemble(protected, other_payload, sig_a).hex())
    check("复用不匹配签名被拒绝", r["verdict"] == "fail" and has_reason(r, "验签失败"),
          json.dumps(r, ensure_ascii=False))

    # 载荷不是 JSON 对象
    r = cose.verify_review(pk_hex, signed_package(protected, b"[1,2,3]", sk))
    check("非对象 JSON 载荷被拒绝", r["verdict"] == "fail" and has_reason(r, "对象"),
          json.dumps(r, ensure_ascii=False))

    # 载荷非法 UTF-8
    r = cose.verify_review(pk_hex, signed_package(protected, b"\xff\xfe{", sk))
    check("非法 UTF-8 载荷被拒绝", r["verdict"] == "fail" and has_reason(r, "UTF-8"),
          json.dumps(r, ensure_ascii=False))

    # 错误公钥
    _, other_pk = make_key()
    r = cose.verify_review(other_pk, signed_package(protected, payload, sk))
    check("错误公钥验签失败", r["verdict"] == "fail" and r["signature_valid"] is False,
          json.dumps(r, ensure_ascii=False))

    return pk_hex, sk, protected, payload


# ------------------------------------------------ 审计引擎单元测试


def audit_unit_tests(pk_hex, sk, protected):
    print("== 单元测试：有理数控件与差分约束审计引擎 ==", flush=True)

    for good in ("0", "-7", "123", "2/5", "-7/3", "-1/2"):
        try:
            parse_canonical(good)
        except RationalError:
            check(f"规范有理数接受 {good!r}", False, "被拒绝")
            break
    else:
        check("规范有理数字符串被接受", True)

    rejected_all = True
    for bad in ("2/4", "3/1", "1/-2", "01", "+1", "1.5", "1/0", "", "00/5", 3):
        try:
            parse_canonical(bad)
            rejected_all = False
            check(f"非规范有理数拒绝 {bad!r}", False, "被错误接受")
            break
        except RationalError:
            pass
    if rejected_all:
        check("非规范有理数字符串全部被拒绝", True)

    def cc(sid, pos, left, right, b):
        return {"source_id": sid, "position": pos, "left": left,
                "right": right, "bound": parse_canonical(b),
                "bound_text": b}

    res = audit.run_audit(
        "D-UT",
        [cc("a000", 0, "y", "x", "-1"),
         cc("b000", 0, "z", "y", "-1")],
    )
    ok = (res["status"] == "feasible"
          and res["assignment"] == {"x": "0", "y": "-1", "z": "-2"}
          and all(c["satisfied"] for c in res["checks"]))
    check("可行系统给出稳定排列赋值与逐约束复算", ok,
          json.dumps(res, ensure_ascii=False))

    res = audit.run_audit(
        "D-UT",
        [cc("c000", 0, "x", "y", "1"),
         cc("d000", 0, "y", "z", "1"),
         cc("e000", 0, "z", "x", "-3")],
    )
    picked = [(c["source_id"], c["position"])
              for c in res["minimum_deletions"]["constraints"]]
    ok = (res["status"] == "infeasible"
          and len(res["negative_cycle"]["constraints"]) == 3
          and res["minimum_deletions"]["count"] == 1
          and picked == [("c000", 0)]
          and all(c["satisfied"] for c in res["checks_after_deletions"]))
    check("负环证据与最少删除（来源/位置稳定决胜）", ok,
          f"picked={picked} body={json.dumps(res, ensure_ascii=False)}")

    res = audit.run_audit(
        "D-UT",
        [cc("f000", 0, "x", "y", "1/3"),
         cc("f000", 1, "y", "x", "-1/2")],
    )
    check("任意精度分数负环裁决",
          res["status"] == "infeasible"
          and res["minimum_deletions"]["count"] == 1,
          json.dumps(res.get("minimum_deletions"), ensure_ascii=False))

    res = audit.run_audit(
        "D-UT",
        [cc("g000", 0, "x", "y", "0"), cc("g000", 1, "y", "x", "-1"),
         cc("h000", 0, "z", "w", "0"), cc("h000", 1, "w", "z", "-1")],
    )
    picked = [c["index"] for c in res["minimum_deletions"]["constraints"]]
    check("双独立负环最少删 2 且字典序决胜",
          res["minimum_deletions"]["count"] == 2 and picked == [0, 2],
          f"picked={picked}")

    def row(rid, obj):
        payload = json.dumps(obj, separators=(",", ":")).encode()
        return {"id": rid, "public_key_hex": pk_hex,
                "package_hex": signed_package(protected, payload, sk)}

    def bnd(left, right, b):
        return {"left": left, "right": right, "bound": b}

    def row_from(rid, detector, items):
        return row(rid, {"detector_id": detector, "constraints": items})

    rows = [
        row_from("r001", "D-COL", [bnd("y", "x", "-1")]),
        row("r002", {"detector_id": "D-COL", "constraints": [
            bnd("z", "y", "-1"), bnd("x", "z", "3")]}),
    ]
    try:
        detector, constraints = audit.collect_constraints(rows, cose.verify_review)
        check("收集带来源约束（含来源编号与数组位置）",
              detector == "D-COL" and len(constraints) == 3
              and constraints[0]["source_id"] == "r001"
              and constraints[2]["position"] == 1,
              f"detector={detector} n={len(constraints)}")
    except audit.AuditReject as exc:
        check("收集带来源约束（含来源编号与数组位置）", False, str(exc))

    def expect_reject(name, rows_like, needle):
        try:
            audit.collect_constraints(rows_like, cose.verify_review)
            check(name, False, "未被拒绝")
        except audit.AuditReject as exc:
            check(name, needle in str(exc), str(exc))

    expect_reject(
        "探测器不一致被拒绝",
        rows + [row_from("r003", "OTHER", [bnd("a", "b", "0")])],
        "探测器不一致",
    )
    expect_reject(
        "非法有理数被拒绝",
        [row_from("r004", "D-COL", [bnd("a", "b", "2/4")])],
        "非法",
    )
    expect_reject(
        "缺少约束字段被拒绝",
        [row("r005", {"detector_id": "D-COL",
                      "constraints": [{"left": "a", "right": "b"}]})],
        "缺少字段",
    )
    bad_sig = sk.sign(cose.sig_structure(protected, b"not json"))
    expect_reject(
        "引用验签失败记录被拒绝",
        [{"id": "r006", "public_key_hex": pk_hex,
          "package_hex": assemble(protected, b"not json", bad_sig).hex()}],
        "验签通过",
    )

# ---------------------------------------------------------------- 构建检查

def build_check():
    print("== 构建检查 ==", flush=True)
    ok = compileall.compile_dir(APP_DIR, quiet=1, maxlevels=5)
    check("应用代码字节码编译", ok)
    try:
        import main  # noqa: F401
        check("应用模块导入（FastAPI 应用装配）", True)
    except Exception as exc:  # pragma: no cover
        check("应用模块导入（FastAPI 应用装配）", False, repr(exc))


# ---------------------------------------------------------------- HTTP 冒烟

def http(method, url, body=None, expect_json=True):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if expect_json else raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw


def http_smoke(pk_hex, sk, protected, payload):
    base = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    print(f"== HTTP 冒烟（{base}）==", flush=True)

    deadline = time.time() + 90
    up = False
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=5) as resp:
                up = resp.status == 200
                if up:
                    break
        except Exception:
            time.sleep(2)
    check("健康检查可访问", up)
    if not up:
        return

    status, _ = http("GET", base + "/", expect_json=False)
    check("页面可访问", status == 200, f"status={status}")

    # 提交有效报文 -> 通过，并持久化可重读
    good = signed_package(protected, payload, sk)
    status, rec = http("POST", base + "/api/reviews",
                       {"public_key_hex": pk_hex, "package_hex": good})
    check("有效报文提交返回通过",
          status == 201 and rec.get("verdict") == "pass" and rec.get("id"),
          f"status={status} body={json.dumps(rec, ensure_ascii=False)}")

    rid = rec.get("id", "")
    status, got = http("GET", f"{base}/api/reviews/{rid}")
    check("按编号重新读取一致",
          status == 200 and got.get("verdict") == "pass"
          and got.get("payload_sha256") == rec.get("payload_sha256"),
          f"status={status}")

    # 篡改载荷 -> 拒绝记录可观察、可重读
    mutated = bytearray(payload)
    mutated[mutated.index(b"4")] ^= 0x01
    sig = sk.sign(cose.sig_structure(protected, payload))
    bad = assemble(protected, bytes(mutated), sig).hex()
    status, rec = http("POST", base + "/api/reviews",
                       {"public_key_hex": pk_hex, "package_hex": bad})
    ok = (status == 201 and rec.get("verdict") == "fail"
          and any("验签失败" in r for r in rec.get("reasons", [])))
    check("篡改报文留下拒绝记录", ok, f"status={status} body={json.dumps(rec, ensure_ascii=False)}")

    status, got = http("GET", f"{base}/api/reviews/{rec.get('id', '')}")
    check("拒绝记录可按编号重读",
          status == 200 and got.get("verdict") == "fail" and got.get("reasons"),
          f"status={status}")

    # 非规范编码经 API 同样被拒绝
    protected_nc = b"\xa2\x02\x41\x01\x01\x27"
    status, rec = http("POST", base + "/api/reviews",
                       {"public_key_hex": pk_hex,
                        "package_hex": signed_package(protected_nc, payload, sk)})
    check("非规范键序经 API 被拒绝",
          status == 201 and rec.get("verdict") == "fail"
          and any("键序" in r for r in rec.get("reasons", [])),
          f"status={status}")

    status, _ = http("GET", base + "/api/reviews/000000000000")
    check("未知编号返回 404", status == 404, f"status={status}")


def audit_http_smoke(pk_hex, sk, protected):
    """审计接口真实 HTTP 覆盖：可行、矛盾、拒绝、冻结读回。"""
    base = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    print(f"== 审计 HTTP 冒烟（{base}）==", flush=True)

    def submit_payload(obj):
        payload = json.dumps(obj, separators=(",", ":")).encode()
        status, rec = http("POST", base + "/api/reviews",
                           {"public_key_hex": pk_hex,
                            "package_hex": signed_package(protected, payload, sk)})
        assert status == 201 and rec.get("verdict") == "pass", (status, rec)
        return rec["id"]

    # ---- 可行：两个来源联立 y-x<=-1、z-y<=-1
    rid_a = submit_payload({"detector_id": "D-FEAS", "constraints": [
        {"left": "y", "right": "x", "bound": "-1"}]})
    rid_b = submit_payload({"detector_id": "D-FEAS", "constraints": [
        {"left": "z", "right": "y", "bound": "-1"}]})
    status, aud = http("POST", base + "/api/audits",
                       {"review_ids": [rid_a, rid_b]})
    ok = (status == 201 and aud.get("status") == "feasible"
          and aud.get("assignment") == {"x": "0", "y": "-1", "z": "-2"}
          and all(c["satisfied"] for c in aud.get("checks", []))
          and {c["source_id"] for c in aud["constraints"]} == {rid_a, rid_b}
          and aud.get("source_review_ids") == [rid_a, rid_b])
    check("可行审计：稳定赋值、逐约束复算、来源可观察", ok,
          f"status={status} body={json.dumps(aud, ensure_ascii=False)}")

    # 刷新/重读审计编号得到同一冻结结果
    audit_id = aud.get("id", "")
    status, refrozen = http("GET", f"{base}/api/audits/{audit_id}")
    check("审计编号读回同一冻结结果",
          status == 200
          and refrozen.get("assignment") == aud.get("assignment")
          and refrozen.get("constraints") == aud.get("constraints")
          and refrozen.get("source_review_ids") == [rid_a, rid_b],
          f"status={status}")

    # ---- 矛盾：三个来源跨包成环，最小删 1，按来源编号稳定决胜
    r1 = submit_payload({"detector_id": "D-CONT", "constraints": [
        {"left": "x", "right": "y", "bound": "1"}]})
    r2 = submit_payload({"detector_id": "D-CONT", "constraints": [
        {"left": "y", "right": "z", "bound": "1"}]})
    r3 = submit_payload({"detector_id": "D-CONT", "constraints": [
        {"left": "z", "right": "x", "bound": "-3"}]})
    status, aud = http("POST", base + "/api/audits",
                       {"review_ids": [r1, r2, r3]})
    md = (aud or {}).get("minimum_deletions", {})
    picked = [(c["source_id"], c["position"]) for c in md.get("constraints", [])]
    ok = (status == 201 and aud.get("status") == "infeasible"
          and len(aud.get("negative_cycle", {}).get("constraints", [])) == 3
          and md.get("count") == 1 and picked == [(min(r1, r2, r3), 0)]
          and all(c["satisfied"]
                  for c in aud.get("checks_after_deletions", [])))
    check("矛盾审计：负环证据、最少删除集与稳定决胜", ok,
          f"status={status} picked={picked} body={json.dumps(aud, ensure_ascii=False)}")

    # 矛盾结果同样冻结
    status, refrozen = http("GET", f"{base}/api/audits/{aud.get('id', '')}")
    check("矛盾审计冻结读回一致",
          status == 200 and refrozen.get("minimum_deletions") == md
          and refrozen.get("status") == "infeasible", f"status={status}")

    # ---- 非法请求一律 400，且不产生审计编号
    def expect_400(name, ids, needle=""):
        status, body = http("POST", base + "/api/audits", {"review_ids": ids})
        detail = body.get("detail", "") if isinstance(body, dict) else ""
        check(name, status == 400 and needle in detail,
              f"status={status} detail={detail}")

    expect_400("未知编号审计被拒绝", ["000000000000"], "无已保存")
    expect_400("重复引用被拒绝", [rid_a, rid_a], "重复")
    expect_400("空引用列表被拒绝", [], "")
    other = submit_payload({"detector_id": "D-OTHER", "constraints": [
        {"left": "a", "right": "b", "bound": "0"}]})
    expect_400("探测器不一致被拒绝", [rid_a, other], "探测器不一致")
    bad_rat = submit_payload({"detector_id": "D-FEAS", "constraints": [
        {"left": "a", "right": "b", "bound": "2/4"}]})
    expect_400("非法有理数被拒绝", [rid_a, bad_rat], "非法")
    miss = submit_payload({"detector_id": "D-FEAS", "constraints": [
        {"left": "a", "right": "b"}]})
    expect_400("缺少约束字段被拒绝", [rid_a, miss], "缺少字段")
    nofield = submit_payload({"detector_id": "D-FEAS"})
    expect_400("载荷缺少 constraints 被拒绝", [rid_a, nofield], "constraints")
    emptylist = submit_payload({"detector_id": "D-FEAS", "constraints": []})
    expect_400("空约束集合被拒绝", [emptylist], "无约束")

    # 被拒绝（验签失败）的复核编号不得引用
    bad_payload = json.dumps({"detector_id": "D-FEAS", "constraints": [
        {"left": "a", "right": "b", "bound": "0"}]}, separators=(",", ":")).encode()
    mutated = bytearray(bad_payload)
    mutated[-1] ^= 0x01
    sig = sk.sign(cose.sig_structure(protected, bad_payload))
    status, rec = http("POST", base + "/api/reviews",
                       {"public_key_hex": pk_hex,
                        "package_hex": assemble(protected, bytes(mutated), sig).hex()})
    assert status == 201 and rec.get("verdict") == "fail"
    expect_400("引用未通过复核记录被拒绝", [rid_a, rec["id"]], "验签通过")

    # 审计列表与 404
    status, lst = http("GET", base + "/api/audits")
    check("审计摘要列表可观察", status == 200 and isinstance(lst, list)
          and any(x.get("id") == audit_id for x in lst), f"status={status}")
    status, _ = http("GET", base + "/api/audits/000000000000")
    check("未知审计编号返回 404", status == 404, f"status={status}")

    # 既有单包复核重读不受影响
    status, got = http("GET", f"{base}/api/reviews/{rid_a}")
    check("既有单包复核重读保持可用",
          status == 200 and got.get("verdict") == "pass", f"status={status}")


# ---------------------------------------------------------------- 主流程

def main():
    pk_hex, sk, protected, payload = unit_tests()
    audit_unit_tests(pk_hex, sk, protected)
    build_check()
    http_smoke(pk_hex, sk, protected, payload)
    audit_http_smoke(pk_hex, sk, protected)

    print(f"\n通过 {len(PASSES)} 项，失败 {len(FAILURES)} 项", flush=True)
    for name, detail in FAILURES:
        print(f"  FAIL: {name}  {detail}", flush=True)
    code = 0 if not FAILURES else 1
    print(f"VERIFY_EXIT_CODE={code}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
