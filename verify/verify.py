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

import cose

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


def signed_payload_package(sk, payload_obj):
    """对含 detector_id/constraints 的 JSON 载荷签名，返回 COSE 报文 hex。"""
    protected = b"\xa1\x01\x27"  # {1: -8} => alg = EdDSA
    raw = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    sig = sk.sign(cose.sig_structure(protected, raw))
    pkg = (b"\x84" + cose.bstr_header(len(protected)) + protected + b"\xa0"
           + cose.bstr_header(len(raw)) + raw + cose.bstr_header(len(sig)) + sig)
    return pkg.hex()


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


def audit_smoke(pk_hex, sk):
    """约束一致性审计：经真实接口覆盖可行、矛盾、冻结重读与拒绝矩阵。"""
    base = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    print("== 约束审计 HTTP 冒烟 ==", flush=True)

    def review_pass(payload):
        status, rec = http("POST", base + "/api/reviews",
                           {"public_key_hex": pk_hex,
                            "package_hex": signed_payload_package(sk, payload)})
        assert status == 201 and rec.get("verdict") == "pass", (status, rec)
        return rec["id"]

    def audit(ids):
        return http("POST", base + "/api/audits", {"review_ids": ids})

    # ---- 可行：同一探测器 D-17，a-b<=-1, b-c<=-2，a-c<=7/2（分数） ----
    f1 = review_pass({"detector_id": "D-17",
                      "constraints": [{"left": "a", "right": "b", "bound": "-1"}]})
    f2 = review_pass({"detector_id": "D-17",
                      "constraints": [{"left": "b", "right": "c", "bound": "-2"}]})
    f3 = review_pass({"detector_id": "D-17",
                      "constraints": [{"left": "a", "right": "c", "bound": "7/2"}]})
    status, rec = audit([f1, f2, f3])
    vals = {a["param"]: a["value"] for a in rec.get("assignment", [])}
    slack = {(c["source_review_id"], c["index"]): c["slack"]
             for c in rec.get("checks", [])}
    lhs = {(c["source_review_id"], c["index"]): c["left_minus_right"]
           for c in rec.get("checks", [])}
    check("可行审计返回满足赋值",
          status == 201 and rec.get("verdict") == "feasible"
          and rec.get("params") == ["a", "b", "c"]
          and vals == {"a": "-3", "b": "-2", "c": "0"}
          and all(c["holds"] for c in rec.get("checks", [])),
          f"status={status} body={json.dumps(rec, ensure_ascii=False)}")
    check("逐约束复算任意精度精确（left−right 与松弛）",
          slack == {(f1, 0): "0", (f2, 0): "0", (f3, 0): "13/2"}
          and lhs == {(f1, 0): "-1", (f2, 0): "-2", (f3, 0): "-3"},
          f"slack={slack} lhs={lhs}")
    aid = rec["id"]
    status, got = http("GET", f"{base}/api/audits/{aid}")
    check("审计编号冻结读回同一可行结果",
          status == 200 and got.get("assignment") == rec.get("assignment")
          and got.get("checks") == rec.get("checks")
          and got.get("sources") == rec.get("sources"),
          f"status={status}")

    # ---- 矛盾：加入 c-a<=-4，与 a-c<=3 构成 a-a<=-1 负环 ----
    f4 = review_pass({"detector_id": "D-17",
                      "constraints": [{"left": "c", "right": "a", "bound": "-4"}]})
    status, rec = audit([f1, f2, f4])
    mc = rec.get("minimal_contradictions", [])
    check("矛盾审计给出最少删除集",
          status == 201 and rec.get("verdict") == "infeasible"
          and len(mc) == 1 and mc[0]["source_review_id"] == min(f1, f2, f4)
          and {e["source_review_id"] for e in rec.get("negative_cycle_evidence", [])},
          f"status={status} body={json.dumps(rec, ensure_ascii=False)}")
    cid = rec["id"]
    status, got = http("GET", f"{base}/api/audits/{cid}")
    check("矛盾审计编号冻结读回一致",
          status == 200 and got.get("minimal_contradictions") == mc
          and got.get("verdict") == "infeasible", f"status={status}")

    # ---- 同包内同大小矛盾按数组位置稳定选择 ----
    f5 = review_pass({"detector_id": "D-2", "constraints": [
        {"left": "x", "right": "y", "bound": "-1"},
        {"left": "m", "right": "n", "bound": "0"},
        {"left": "y", "right": "x", "bound": "-1"},
    ]})
    status, rec = audit([f5])
    mc5 = rec.get("minimal_contradictions", [])
    check("同包矛盾按数组位置稳定",
          status == 201 and len(mc5) == 1 and mc5[0]["index"] == 0,
          json.dumps(rec, ensure_ascii=False))

    # 输入顺序无关：颠倒来源次序，最小矛盾集必须完全一致
    def ids_of(rec):
        return sorted((c["source_review_id"], c["index"])
                      for c in rec.get("minimal_contradictions", []))
    status, rA = audit([f1, f2, f4])
    status, rB = audit([f4, f1, f2])
    check("审计结论与引用顺序无关",
          rA.get("verdict") == "infeasible" and ids_of(rA) == ids_of(rB),
          f"{ids_of(rA)} vs {ids_of(rB)}")

    # 空 constraints：可行、空赋值，来源仍保留；不同探测器仍拒绝
    fe = review_pass({"detector_id": "D-17", "constraints": []})
    status, rec = audit([fe])
    check("空约束判可行且保留来源",
          status == 201 and rec.get("verdict") == "feasible"
          and rec.get("params") == [] and rec.get("assignment") == []
          and [s["review_id"] for s in rec.get("sources", [])] == [fe],
          json.dumps(rec, ensure_ascii=False))
    fe2 = review_pass({"detector_id": "D-OTHER", "constraints": []})
    status, rec = audit([fe, fe2])
    check("空约束来源探测器不一致仍拒绝",
          status == 400 and "探测器不一致" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")

    # ---- 拒绝矩阵：均不得生成审计编号 ----
    status, rec = audit([f1, f5])
    check("探测器不一致被拒绝",
          status == 400 and "探测器不一致" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")
    status, rec = audit([f1, f1])
    check("重复引用被拒绝",
          status == 400 and "重复" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")
    status, rec = audit([f1, "000000000000"])
    check("无通过记录编号被拒绝",
          status == 400 and "无通过记录" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")
    status, rec = audit([])
    check("空引用被拒绝", status == 400, f"status={status}")

    # 引用未通过（篡改）记录
    good_raw = json.dumps({"detector_id": "D-17", "constraints": []}).encode()
    protected = b"\xa1\x01\x27"
    sig = sk.sign(cose.sig_structure(protected, good_raw))
    tampered = bytearray(good_raw)
    tampered[tampered.index(b"D-17") + 2] = ord("2")
    bad = (b"\x84" + cose.bstr_header(len(protected)) + protected + b"\xa0"
           + cose.bstr_header(len(tampered)) + bytes(tampered)
           + cose.bstr_header(len(sig)) + sig).hex()
    status, fr = http("POST", base + "/api/reviews",
                      {"public_key_hex": pk_hex, "package_hex": bad})
    bad_id = fr.get("id", "")
    check("篡改载荷复核未通过", status == 201 and fr.get("verdict") == "fail",
          json.dumps(fr, ensure_ascii=False))
    status, rec = audit([bad_id])
    check("引用未通过记录被拒绝",
          status == 400 and "未通过验签" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")

    # 缺字段 / 非法有理数
    g_no_c = review_pass({"detector_id": "D-9"})
    status, rec = audit([g_no_c])
    check("缺少 constraints 被拒绝",
          status == 400 and "constraints" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")
    g_bad_q = review_pass({"detector_id": "D-3",
                           "constraints": [{"left": "a", "right": "b",
                                            "bound": "2/4"}]})
    status, rec = audit([g_bad_q])
    check("非法有理数 2/4 被拒绝",
          status == 400 and "规范" in json.dumps(rec, ensure_ascii=False),
          f"status={status}")

    # 被拒后旧审计仍可读
    status, got = http("GET", f"{base}/api/audits/{cid}")
    check("拒绝不影响既有冻结审计", status == 200 and got.get("id") == cid,
          f"status={status}")
    status, _ = http("GET", base + "/api/audits/000000000000")
    check("未知审计编号返回 404", status == 404, f"status={status}")
    status, _ = http("GET", base + "/api/audits")
    check("审计列表可访问", status == 200, f"status={status}")


# ---------------------------------------------------------------- 主流程

def main():
    pk_hex, sk, protected, payload = unit_tests()
    build_check()
    http_smoke(pk_hex, sk, protected, payload)
    audit_smoke(pk_hex, sk)

    print(f"\n通过 {len(PASSES)} 项，失败 {len(FAILURES)} 项", flush=True)
    for name, detail in FAILURES:
        print(f"  FAIL: {name}  {detail}", flush=True)
    code = 0 if not FAILURES else 1
    print(f"VERIFY_EXIT_CODE={code}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
