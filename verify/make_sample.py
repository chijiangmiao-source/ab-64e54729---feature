#!/usr/bin/env python3
"""生成一份有效的 COSE_Sign1 样例（公钥 + 报文 hex），用于页面手工联调。"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import cose

sk = Ed25519PrivateKey.generate()
pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
protected = b"\xa1\x01\x27"  # {1: -8} => alg = EdDSA
payload = b'{"device":"ir-cal-01","dose_uGy":4200,"batch":"B7","ts":"2026-09-26T08:00:00Z"}'
sig = sk.sign(cose.sig_structure(protected, payload))
def bstr(b):
    return cose.bstr_header(len(b)) + b


pkg = b"\x84" + bstr(protected) + b"\xa0" + bstr(payload) + bstr(sig)

print("PUBLIC_KEY_HEX=" + pk.hex())
print("PACKAGE_HEX=" + pkg.hex())
