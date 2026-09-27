"""严格确定性 CBOR 解码器（RFC 8949 确定性编码子集）。

任何偏离确定性编码的字节序列都会被拒绝，保证解析结果与原始字节
一一对应，防止“解析后重新序列化”掩盖篡改：

- 拒绝不定长（indefinite-length）编码；
- 整数与长度必须使用最短形式；
- 映射键不得重复，且必须按规范键序（先编码长度、后字节序）严格升序；
- 拒绝浮点数与简单值（major type 7）；
- 仅允许已声明的标签（COSE_Sign1 = 18）。
"""

from __future__ import annotations


class CBORError(ValueError):
    """CBOR 数据非法或违反确定性编码规则。"""


class Tagged:
    """CBOR 标签项。"""

    __slots__ = ("tag", "value")

    def __init__(self, tag: int, value):
        self.tag = tag
        self.value = value


class CBORMap:
    """保持原始顺序的 CBOR 映射（重复键已在解码阶段被拒绝）。"""

    __slots__ = ("pairs",)

    def __init__(self, pairs):
        self.pairs = pairs

    def get(self, key, default=None):
        for k, v in self.pairs:
            if k == key:
                return v
        return default

    def items(self):
        return list(self.pairs)

    def __contains__(self, key):
        return any(k == key for k, _ in self.pairs)

    def __len__(self):
        return len(self.pairs)


ALLOWED_TAGS = frozenset({18})  # COSE_Sign1
_MAX_DEPTH = 64


def _key_before(a: bytes, b: bytes) -> bool:
    """规范键序：先按编码长度，再按字节序（无符号）比较。"""
    return (len(a), a) < (len(b), b)


class _Decoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CBORError("CBOR 数据被截断")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def argument(self, info: int) -> int:
        if info < 24:
            return info
        if info == 24:
            value, floor = self.read(1)[0], 24
        elif info == 25:
            value, floor = int.from_bytes(self.read(2), "big"), 0x100
        elif info == 26:
            value, floor = int.from_bytes(self.read(4), "big"), 0x10000
        elif info == 27:
            value, floor = int.from_bytes(self.read(8), "big"), 0x100000000
        else:
            raise CBORError(f"非法的附加信息值 {info}")
        if value < floor:
            raise CBORError("非最短形式的整数/长度编码")
        return value

    def item(self, depth: int):
        if depth > _MAX_DEPTH:
            raise CBORError("CBOR 嵌套过深")
        ib = self.read(1)[0]
        major, info = ib >> 5, ib & 0x1F
        if info == 31:
            raise CBORError("拒绝不定长（indefinite-length）编码")
        if major == 0:
            return self.argument(info)
        if major == 1:
            return -1 - self.argument(info)
        if major == 2:
            return self.read(self.argument(info))
        if major == 3:
            raw = self.read(self.argument(info))
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORError("文本字符串不是合法 UTF-8") from exc
        if major == 4:
            return [self.item(depth + 1) for _ in range(self.argument(info))]
        if major == 5:
            pairs = []
            prev_raw = None
            for _ in range(self.argument(info)):
                kstart = self.pos
                key = self.item(depth + 1)
                kraw = self.data[kstart:self.pos]
                if prev_raw is not None:
                    if kraw == prev_raw:
                        raise CBORError("映射包含重复键")
                    if not _key_before(prev_raw, kraw):
                        raise CBORError("映射键序不符合规范（须按编码长度再按字节序升序）")
                prev_raw = kraw
                pairs.append((key, self.item(depth + 1)))
            return CBORMap(pairs)
        if major == 6:
            tag = self.argument(info)
            if tag not in ALLOWED_TAGS:
                raise CBORError(f"未声明的 CBOR 标签 {tag}")
            return Tagged(tag, self.item(depth + 1))
        raise CBORError("拒绝浮点数/简单值（major type 7）")


def decode(data: bytes):
    """严格解码完整缓冲区；任何违规抛出 CBORError。"""
    if not data:
        raise CBORError("CBOR 数据为空")
    dec = _Decoder(bytes(data))
    value = dec.item(0)
    if dec.pos != len(dec.data):
        raise CBORError("CBOR 数据末尾存在多余字节")
    return value
