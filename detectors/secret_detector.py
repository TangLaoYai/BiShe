"""模块3-3：敏感信息硬编码检测 —— HardcodedSecretDetector

合约源码永久公开在链上，任何写入源码的密钥、口令、管理员地址都会暴露给所有人，
且无法通过升级掩盖。本检测器扫描以下四类硬编码风险：

1. 硬编码私钥：32 字节（64 位十六进制）私钥直接写在源码中 —— 高危、置信度高
2. 硬编码管理员地址：owner/admin 等角色初始化为固定地址 —— 中危、置信度高
3. 硬编码口令/密钥字符串：password/secret/apiKey 直接赋值 —— 高危、置信度中
4. ecrecover 签名校验：需确认返回值校验与 nonce 防重放 —— 中危、置信度中

规则只做静态模式匹配，先剔除注释避免注释中的示例哈希误报。
"""
import re

from .base import BaseDetector, register
from services.solc_parser import parse_source

RISK_HIGH, RISK_MID = "高危", "中危"

# 64 位十六进制私钥（可带 0x 前缀）
PRIVATE_KEY_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")
# 角色地址硬编码：owner / admin / manager / creator 等初始化为固定地址
ROLE_ADDR_RE = re.compile(
    r"\b(owner|admin|manager|creator|controller|operator)\s*=\s*"
    r"(?:payable\s*\(\s*)?0x[0-9a-fA-F]{40}\b", re.I)
# 口令 / 密钥字符串硬编码
SECRET_STR_RE = re.compile(
    r"\b(password|passwd|secret|apiKey|api_key|privateKey|private_key|mnemonic)\b"
    r"\s*=\s*\"[^\"]{3,}\"", re.I)
# 签名校验
ECRECOVER_RE = re.compile(r"\becrecover\s*\(", re.I)


def _strip_comments(source: str) -> str:
    """去除注释后扫描，避免注释里的示例哈希/地址误报。

    用等长空白替换注释（保留换行），使命中偏移与原文一致，保证行号准确。
    """
    source = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                    source, flags=re.S)
    source = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), source)
    return source


def _line_of(source: str, pos: int) -> int:
    return source.count("\n", 0, pos) + 1


@register
class HardcodedSecretDetector(BaseDetector):
    """敏感信息硬编码检测插件（私钥 / 管理员地址 / 口令字符串 / ecrecover）"""
    name = "secret_detector"
    description = "敏感信息硬编码检测（源码公开可见，密钥口令不可写入合约）"

    def detect(self, contract_info: dict) -> list:
        source = contract_info.get("source_code") or ""
        if not source:
            return []
        code = _strip_comments(source)
        # 解析结果用于定位所在函数，解析失败也不影响规则扫描
        info = contract_info.get("parse") or parse_source(source)
        vulns = []

        for m in PRIVATE_KEY_RE.finditer(code):
            line = _line_of(source, m.start())
            vulns.append({
                "vul_type": "硬编码私钥泄露",
                "risk_level": RISK_HIGH,
                "confidence": "高",
                "location": f"第{line}行 {self._context(code, m.start())}",
                "description": "源码中出现 64 位十六进制字符串，形态与以太坊私钥一致。"
                               "合约源码在链上永久公开，私钥一经写入即可被任何人获取并转移资产。",
                "suggestion": "立即废弃并转移该私钥对应账户的资产；"
                              "私钥绝不可写入合约源码，签名操作应放在链下由密钥管理服务完成。",
            })
            break  # 私钥只需报首个位置

        for m in ROLE_ADDR_RE.finditer(code):
            line = _line_of(source, m.start())
            vulns.append({
                "vul_type": "管理员地址硬编码",
                "risk_level": RISK_MID,
                "confidence": "高",
                "location": f"第{line}行 {m.group(0).strip()}",
                "description": f"角色变量 {m.group(1)} 被初始化为固定的 0x 地址。"
                               "若该地址私钥丢失或权限变更，合约管理权将无法转移，"
                               "且固定地址容易被针对性攻击。",
                "suggestion": "改为在构造函数中通过 msg.sender 赋值，"
                              "或使用 Ownable 等标准权限模式并提供 transferOwnership。",
            })
            break  # 同类问题只报首个位置

        for m in SECRET_STR_RE.finditer(code):
            line = _line_of(source, m.start())
            vulns.append({
                "vul_type": "口令密钥硬编码",
                "risk_level": RISK_HIGH,
                "confidence": "中",
                "location": f"第{line}行 {m.group(1)} = \"***\"",
                "description": f"变量 {m.group(1)} 被赋值为字符串常量。"
                               "合约源码公开可见，硬编码的口令/密钥等同于公开泄露，"
                               "且修改必须重新部署合约。",
                "suggestion": "移除源码中的口令与密钥，改为链下密钥管理 + 链上哈希校验，"
                              "或通过构造函数/权限合约动态注入。",
            })
            break

        for m in ECRECOVER_RE.finditer(code):
            line = _line_of(source, m.start())
            vulns.append({
                "vul_type": "ecrecover签名校验风险",
                "risk_level": RISK_MID,
                "confidence": "中",
                "location": f"第{line}行 ecrecover(...)",
                "description": "使用 ecrecover 恢复签名地址。若未校验返回值非零地址、"
                               "未限制签名用途与 nonce，攻击者可重放历史签名重复执行敏感操作。",
                "suggestion": "校验 ecrecover 返回值不为 address(0)，"
                              "并在签名内容中绑定 nonce、chainId 与业务用途，防止重放。",
            })
            break

        return vulns

    @staticmethod
    def _context(code: str, pos: int) -> str:
        """截取命中位置所在行的前若干字符作为定位提示"""
        start = code.rfind("\n", 0, pos) + 1
        end = code.find("\n", pos)
        line = code[start:end if end > 0 else len(code)].strip()
        return (line[:60] + "…") if len(line) > 60 else line
