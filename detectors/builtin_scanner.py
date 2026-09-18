"""内置规则静态扫描器（Slither 降级保障）

当虚拟机/WSL 内 Slither 不可用时（subprocess 失败、超时、未安装），
SlitherDetector 自动降级为本模块的规则扫描，保证宿主机独立可跑通全流程。
规则基于正则静态分析，覆盖常见 Solidity 漏洞模式。
"""
import re

from .base import BaseDetector

RISK_HIGH, RISK_MID, RISK_LOW = "高危", "中危", "低危"


def _line_of(source: str, pos: int) -> int:
    return source.count("\n", 0, pos) + 1


def _strip_comments(source: str) -> str:
    """去除注释后扫描，避免误报"""
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return source


RULES = [
    {
        "type": "tx.origin鉴权缺陷",
        "level": RISK_HIGH,
        "pattern": r"\btx\.origin\b",
        "desc": "代码中使用 tx.origin 做身份校验，存在钓鱼合约中间人攻击风险："
                "受害者在钓鱼合约触发本合约代码时，tx.origin 仍是受害者地址，导致鉴权被绕过。",
        "suggestion": "使用 msg.sender 替代 tx.origin 进行权限校验。",
    },
    {
        "type": "危险delegatecall",
        "level": RISK_HIGH,
        "pattern": r"\.\s*delegatecall\s*\(",
        "desc": "存在 delegatecall 调用，目标合约代码会在本合约上下文执行并可直接修改本合约状态，"
                "若目标地址可被外部控制将导致任意代码执行。",
        "suggestion": "固定 delegatecall 目标地址且不依赖用户输入；升级逻辑请使用成熟代理模式并加强权限控制。",
    },
    {
        "type": "任意自毁",
        "level": RISK_HIGH,
        "pattern": r"\bselfdestruct\s*\(",
        "desc": "存在 selfdestruct 调用，若自毁入口无权限控制或目标可指定，合约将被销毁且资金可被强制转移。",
        "suggestion": "为 selfdestruct 添加 onlyOwner 等强权限校验，并审计其调用路径。",
    },
    {
        "type": "外部调用重入风险",
        "level": RISK_MID,
        "pattern": r"\.\s*call\s*\{?|\.\s*transfer\s*\(|\.\s*send\s*\(",
        "desc": "函数内存在对外部地址的以太转账/调用，若在状态更新前执行且无重入保护，攻击者可利用 "
                "fallback 重入本函数重复提取资金。",
        "suggestion": "遵循 Checks-Effects-Interactions 模式，先更新状态再外部调用，"
                      "并引入 ReentrancyGuard 的 nonReentrant 修饰符。",
        "in_function": True,
        "guard_pattern": r"\bnonReentrant\b",
    },
    {
        "type": "未检查底层调用返回值",
        "level": RISK_LOW,
        "pattern": r"\.\s*call\s*\{?value?",
        "desc": "底层 call 调用的返回值（bool）未被检查，调用失败时不会回滚，"
                "可能导致合约状态与资金流不一致。",
        "suggestion": "对 call 返回值使用 require 判断，或改用带返回值检查的封装。",
    },
    {
        "type": "时间戳依赖",
        "level": RISK_LOW,
        "pattern": r"\bblock\.timestamp\b|\bnow\b",
        "desc": "逻辑依赖区块时间戳，矿工可在一定范围内操纵时间戳影响关键判定。",
        "suggestion": "不要将 block.timestamp 作为随机源或强依赖的判定条件；"
                      "关键逻辑使用区块高度等更稳定的量。",
    },
    {
        "type": "弱随机数",
        "level": RISK_MID,
        "pattern": r"\bblockhash\s*\(|\bblock\.(difficulty|number)\b",
        "desc": "使用区块属性作为随机源，矿工可影响区块属性从而操纵随机结果。",
        "suggestion": "改用 Chainlink VRF 等链上安全随机数方案，或 commit-reveal 模式。",
    },
]


class BuiltinScannerDetector(BaseDetector):
    """内置规则静态扫描器（SlitherDetector 的降级实现，不注册到插件注册器，
    仅在 Slither 不可用时由 SlitherDetector 内部调用，避免重复检测）"""
    name = "builtin_scanner"
    description = "内置正则规则静态扫描（Slither 不可用时自动启用）"

    def detect(self, contract_info: dict) -> list:
        source = contract_info.get("source_code") or ""
        if not source:
            return []
        code = _strip_comments(source)
        # 判断编译版本是否低于 0.8.0（低版本整数溢出不自动检查）
        low_version = False
        pm = re.search(r"pragma\s+solidity\s*[\^>=]*\s*0\.(\d+)", code)
        if pm and int(pm.group(1)) < 8:
            low_version = True
        has_safemath = "SafeMath" in code

        vulns = []
        for rule in RULES:
            for m in re.finditer(rule["pattern"], code):
                # 函数级规则：若函数带重入保护则跳过
                if rule.get("in_function"):
                    fn = self._find_function(code, m.start())
                    if fn and re.search(rule["guard_pattern"], fn):
                        continue
                vulns.append({
                    "vul_type": rule["type"],
                    "risk_level": rule["level"],
                    "location": f"第{_line_of(source, self._raw_pos(source, code, m.start()))}行",
                    "description": rule["desc"],
                    "suggestion": rule["suggestion"],
                })
                break  # 同类漏洞只报首个位置，避免刷屏

        # 低版本无 SafeMath 的算术溢出
        if low_version and not has_safemath and re.search(r"[+\-*]", code):
            vulns.append({
                "vul_type": "整数溢出风险",
                "risk_level": RISK_MID,
                "location": "全局",
                "description": "编译版本低于 0.8.0 且未引入 SafeMath，加减乘运算可能发生整数上溢/下溢。",
                "suggestion": "升级编译器至 ^0.8.0，或全部算术运算改用 SafeMath 库。",
            })
        return vulns

    def _find_function(self, code: str, pos: int) -> str:
        """返回包含 pos 位置的最近函数体文本（简化：向前找最近 function 关键字取其体）"""
        idx = code.rfind("function", 0, pos)
        if idx < 0:
            return ""
        brace = code.find("{", idx)
        if brace < 0:
            return ""
        end = code.find("}", brace)
        return code[idx:end + 1 if end > 0 else brace]

    def _raw_pos(self, source: str, code: str, code_pos: int) -> int:
        """粗略将去注释后的偏移映射回原文本偏移（前后按同源截断近似）"""
        return min(code_pos, len(source) - 1)
