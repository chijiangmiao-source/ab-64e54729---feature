"""COSE_Sign1 复核逻辑。

验签使用报文中的原始受保护头字节与原始载荷字节构造 Sig_structure，
绝不由解析后的对象重新编码，避免重新序列化掩盖篡改。
"""

from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cbor_strict import CBORError, CBORMap, Tagged, decode

EDDSA_ALG = -8   # COSE alg 标识：EdDSA
ALG_LABEL = 1    # COSE 受保护头标签：alg


def bstr_header(length: int) -> bytes:
    """确定性（最短形式）字节串头。"""
    if length < 24:
        return bytes([0x40 + length])
    if length < 0x100:
        return b"\x58" + bytes([length])
    if length < 0x10000:
        return b"\x59" + length.to_bytes(2, "big")
    if length < 0x100000000:
        return b"\x5a" + length.to_bytes(4, "big")
    return b"\x5b" + length.to_bytes(8, "big")


def sig_structure(protected_raw: bytes, payload_raw: bytes, external_aad: bytes = b"") -> bytes:
    """COSE Sig_structure 的确定性编码（context = "Signature1"）。

    protected_raw / payload_raw 必须是报文中的原始字节，
    禁止用解析后的对象重新编码替代。
    """
    return (
        b"\x84"                    # array(4)
        b"\x6aSignature1"          # text(10) "Signature1"
        + bstr_header(len(protected_raw)) + protected_raw
        + bstr_header(len(external_aad)) + external_aad
        + bstr_header(len(payload_raw)) + payload_raw
    )


def _display(value):
    if isinstance(value, CBORMap):
        return {_display_key(k): _display(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_display(v) for v in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, Tagged):
        return {"tag": value.tag, "value": _display(value.value)}
    return value


def _display_key(key):
    if isinstance(key, (int, str)):
        return str(key)
    if isinstance(key, bytes):
        return "hex:" + key.hex()
    return json.dumps(_display(key), ensure_ascii=False)


def verify_review(public_key_hex: str, package_hex: str) -> dict:
    """复核一份 COSE_Sign1 校准包，返回结论与逐项拒绝原因。

    通过条件（缺一不可）：受保护头显式声明 EdDSA、载荷为 UTF-8 JSON
    对象、基于原始字节构造的 Sig_structure 验签有效、且全部严格解析
    检查无拒绝原因。
    """
    reasons = []
    protected_headers = None
    payload_sha256 = None
    signature_valid = None
    alg_ok = False
    payload_json_ok = False

    # ---- 公钥 ----
    pk_bytes = None
    try:
        candidate = bytes.fromhex(public_key_hex.strip())
    except ValueError:
        reasons.append("Ed25519 公钥不是合法十六进制")
    else:
        if len(candidate) != 32:
            reasons.append(f"Ed25519 公钥须为 32 字节，实际 {len(candidate)} 字节")
        else:
            pk_bytes = candidate

    # ---- 报文十六进制 ----
    package = None
    try:
        candidate = bytes.fromhex(package_hex.strip())
    except ValueError:
        reasons.append("COSE_Sign1 报文不是合法十六进制")
    else:
        if not candidate:
            reasons.append("COSE_Sign1 报文为空")
        else:
            package = candidate

    # ---- 严格解析 COSE_Sign1 顶层结构 ----
    protected_raw = payload_raw = signature = None
    if package is not None:
        try:
            top = decode(package)
        except CBORError as exc:
            reasons.append(f"CBOR 严格解析失败：{exc}")
        else:
            if isinstance(top, Tagged):
                top = top.value  # 标签值已在解码阶段限定为 18 (COSE_Sign1)
            if not isinstance(top, list) or len(top) != 4:
                reasons.append("COSE_Sign1 必须是 4 元素数组 [protected, unprotected, payload, signature]")
            else:
                protected_raw, unprotected, payload_raw, signature = top
                if not isinstance(protected_raw, bytes):
                    reasons.append("受保护头（protected）必须是字节串")
                    protected_raw = None
                if not isinstance(unprotected, CBORMap):
                    reasons.append("未保护头（unprotected）必须是映射")
                if not isinstance(payload_raw, bytes):
                    reasons.append("载荷（payload）必须是字节串")
                    payload_raw = None
                if not isinstance(signature, bytes):
                    reasons.append("签名（signature）必须是字节串")
                    signature = None

    # ---- 受保护头：严格解析 + 算法检查 ----
    if protected_raw is not None:
        protected_map = None
        if protected_raw == b"":
            protected_map = CBORMap([])
            protected_headers = {}
        else:
            try:
                parsed = decode(protected_raw)
            except CBORError as exc:
                reasons.append(f"受保护头严格解析失败：{exc}")
            else:
                if not isinstance(parsed, CBORMap):
                    reasons.append("受保护头内容必须是 CBOR 映射")
                else:
                    protected_map = parsed
                    protected_headers = _display(parsed)
        if protected_map is not None:
            alg = protected_map.get(ALG_LABEL, protected_map.get("alg"))
            if alg is None:
                reasons.append("受保护头未显式声明 alg（必须指定 EdDSA/-8）")
            elif alg == EDDSA_ALG or alg == "EdDSA":
                alg_ok = True
            else:
                reasons.append(f"未声明的 COSE 算法 {alg!r}：仅允许 EdDSA（-8）")

    # ---- 载荷：UTF-8 JSON 对象 + 原始字节摘要 ----
    if payload_raw is not None:
        payload_sha256 = hashlib.sha256(payload_raw).hexdigest()
        try:
            text = payload_raw.decode("utf-8")
        except UnicodeDecodeError:
            reasons.append("载荷不是合法 UTF-8")
        else:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                reasons.append("载荷不是合法 JSON")
            else:
                if isinstance(obj, dict):
                    payload_json_ok = True
                else:
                    reasons.append("载荷 JSON 必须是对象")

    # ---- 验签：以原始受保护头字节与原始载荷构造 Sig_structure ----
    if (pk_bytes is not None and protected_raw is not None
            and payload_raw is not None and signature is not None):
        if len(signature) != 64:
            signature_valid = False
            reasons.append(f"Ed25519 签名须为 64 字节，实际 {len(signature)} 字节")
        else:
            to_sign = sig_structure(protected_raw, payload_raw)
            try:
                Ed25519PublicKey.from_public_bytes(pk_bytes).verify(signature, to_sign)
                signature_valid = True
            except InvalidSignature:
                signature_valid = False
                reasons.append("签名与原始字节不匹配（验签失败）")
    elif package is not None:
        reasons.append("因前置检查失败，未执行验签")

    verdict = "pass" if (
        not reasons and signature_valid is True and alg_ok and payload_json_ok
    ) else "fail"
    return {
        "verdict": verdict,
        "public_key_hex": public_key_hex.strip(),
        "package_sha256": hashlib.sha256(package).hexdigest() if package is not None else None,
        "protected_headers": protected_headers,
        "payload_sha256": payload_sha256,
        "signature_valid": signature_valid,
        "reasons": reasons,
    }
