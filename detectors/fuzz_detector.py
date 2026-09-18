"""模块3-2：参数边界 Fuzz 检测 —— BoundaryFuzzDetector（核心创新点之一）

借鉴渗透测试"输入边界测试"思想，仅针对 uint/int 数值类型参数：
- 自动识别对外接口（public/external）入参中的 uint/int 类型
- 构造三类边界测试值：0、对应类型最大值（如 uint256 最大值）、负数（int 适用）
- 静态检测函数体是否缺失对该参数的范围校验（require/if 比较），
  缺失则标记"参数边界校验缺失风险"
"""
import re

from .base import BaseDetector, register
from services.solc_parser import parse_source, format_params

RISK_MID = "中危"
INT_TYPE_RE = re.compile(r"^(u?int)(\d{1,3})?$", re.I)


def _type_max_bits(base: str, bits: int) -> str:
    """生成类型最大值文本，如 uint256 最大值 2^256-1"""
    if base.lower() == "uint":
        return str(2 ** bits - 1)
    return str(2 ** (bits - 1) - 1)


@register
class BoundaryFuzzDetector(BaseDetector):
    """uint/int 参数边界 Fuzz 检测插件"""
    name = "boundary_fuzz"
    description = "uint/int 数值参数边界Fuzz测试（渗透测试输入边界思想）"

    def detect(self, contract_info: dict) -> list:
        source = contract_info.get("source_code") or ""
        info = contract_info.get("parse") or parse_source(source)
        vulns = []
        for fn in info.get("functions", []):
            if fn.get("visibility") not in ("public", "external"):
                continue
            if fn["name"] in ("constructor", "receive", "fallback"):
                continue
            body = fn.get("body", "")
            for param in fn.get("params", []):
                m = INT_TYPE_RE.match(param["type"])
                if not m:
                    continue
                base = m.group(1)
                bits = int(m.group(2) or 256)
                pname = param["name"] or param["type"]
                if self._has_validation(body, param["name"]):
                    continue
                # 构造三类边界测试值：0、类型最大值、负数
                cases = ["0", _type_max_bits(base, bits)]
                if base.lower() == "int":
                    cases.append(f"-1（负数）")
                else:
                    cases.append("负数（uint 下溢回滚，链上视为无效输入）")
                vulns.append({
                    "vul_type": "参数边界校验缺失风险",
                    "risk_level": RISK_MID,
                    "location": f"第{fn['line']}行 {fn['name']}({format_params(fn['params'])}) 参数 {pname}",
                    "description": (
                        f"对外接口 {fn['name']} 的数值参数 {pname}（{param['type']}，{bits}位）"
                        f"未检测到 require/if 范围校验。渗透测试边界 Fuzz 输入 "
                        f"[{', '.join(cases)}] 时，超范围值可直达业务逻辑，"
                        f"可能引发下溢/上溢、索引越界或逻辑绕过。"
                    ),
                    "suggestion": (
                        f"在函数入口对 {pname} 添加范围校验，"
                        f"如 require({pname} > 0 && {pname} <= 合理上限)，"
                        f"拦截 0、类型最大值（{_type_max_bits(base, bits)}）等边界输入。"
                    ),
                })
        return vulns

    def _has_validation(self, body: str, pname: str) -> bool:
        """判断函数体是否对参数做了范围/合法性校验"""
        if not pname or not body:
            return False
        # require(...) 中出现该参数
        for m in re.finditer(r"require\s*\(([^;]*?)\)\s*;", body, re.S):
            if re.search(rf"\b{re.escape(pname)}\b", m.group(1)):
                return True
        # if(...) 且含比较运算符中出现该参数
        for m in re.finditer(r"if\s*\(([^)]*)\)", body):
            cond = m.group(1)
            if re.search(rf"\b{re.escape(pname)}\b", cond) and \
                    re.search(r"(<|>|>=|<=|==|!=)", cond):
                return True
        return False
