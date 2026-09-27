"""规范有理数字符串与任意精度有理数运算。

审计载荷中的上界必须以 *规范* 有理数字符串声明：

- 整数：``0`` 或十进制非零整数（如 ``-7``、``123``），禁止前导零与 ``+`` 号；
- 分数：``整数/正整数``，分母大于 1、不得为负，且分子分母已约分
  （如 ``2/5``、``-7/3``）；``3/1``、``2/4``、``1/-2`` 均为非规范形式。

运算一律使用 :class:`fractions.Fraction`，保证任意精度、无浮点误差。
"""

from __future__ import annotations

import re
from fractions import Fraction

# 整数部分：仅 "0" 或无符号/负号的非零十进制数；分母：正整数（首位非 0）。
_RATIONAL_RE = re.compile(r"^(0|-?[1-9][0-9]*)(?:/([1-9][0-9]*))?$")


class RationalError(ValueError):
    """字符串不是规范有理数。"""


def parse_canonical(text) -> Fraction:
    """把规范有理数字符串解析为 Fraction；任何偏离规范形式的输入均拒绝。"""
    if not isinstance(text, str):
        raise RationalError("上界必须是字符串")
    match = _RATIONAL_RE.fullmatch(text)
    if match is None:
        raise RationalError(f"不是规范有理数字符串：{text!r}")
    numerator_text, denominator_text = match.groups()
    numerator = int(numerator_text)
    if denominator_text is None:
        return Fraction(numerator)
    denominator = int(denominator_text)
    if denominator == 1:
        raise RationalError(f"分母为 1 时须写为整数形式：{text!r}")
    value = Fraction(numerator, denominator)
    # 正则已排除负分母；此处兜底确认约分结果与书写一致。
    if value.numerator != numerator or value.denominator != denominator:
        raise RationalError(f"分数未约分（非规范形式）：{text!r}")
    return value


def format_rational(value: Fraction) -> str:
    """把 Fraction 输出为规范有理数字符串。"""
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator}/{value.denominator}"
