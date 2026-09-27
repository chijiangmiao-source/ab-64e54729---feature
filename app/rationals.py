"""规范有理数字符串（任意精度）。

唯一接受的书写形式（与 ``fractions.Fraction`` 的标准字符串一致）：

- ``0``
- 十进制整数：``4`` / ``-7``（无前导零、无 ``+`` 号、无 ``-0``）
- 最简分数：``3/2`` / ``-5/3``（分母为正整数、分子分母互质、
  分母不得为 1——可整除时必须写成整数）

任何其他形式（``1.5``、``1/0``、``2/4``、``+1``、``-0`` …）一律视为
非法有理数，由调用方直接拒绝审计。
"""

from __future__ import annotations

import re
from fractions import Fraction

# 组 1：分子（0 或无前导零的带符号整数）；组 2：可选分母（正整数、非 0）
_TOKEN_RE = re.compile(r"^(0|-?(?:0|[1-9][0-9]*))(?:/([1-9][0-9]*))?$")


class RationalError(ValueError):
    """有理数字符串非法或不是规范形式。"""


def parse_rational(text) -> Fraction:
    """把规范有理数字符串解析为 Fraction，任何偏离规范的写法都拒绝。"""
    if not isinstance(text, str):
        raise RationalError(f"有理数必须以字符串声明，实际为 {type(text).__name__}")
    match = _TOKEN_RE.fullmatch(text)
    if match is None:
        raise RationalError(f"非法有理数字符串：{text!r}")
    numerator = int(match.group(1))
    denominator = int(match.group(2)) if match.group(2) is not None else 1
    value = Fraction(numerator, denominator)
    if text != str(value):
        raise RationalError(f"有理数不是规范形式（应写为 {str(value)}）：{text!r}")
    return value


def format_rational(value: Fraction) -> str:
    """Fraction 的规范字符串（与 parse_rational 互逆）。"""
    return str(value)
