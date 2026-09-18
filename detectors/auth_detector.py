"""模块3-1：接口暴露/权限检测 —— AuthDetector（核心创新点之一）

模拟渗透测试中的"接口探测"思想：
识别无权限修饰的 public/external 函数，标记为"未授权访问风险"。
- 跳过构造函数、receive/fallback、内部函数
- 已带常见权限修饰符（onlyOwner 等）或函数体内校验 msg.sender 的视为安全
- 状态写函数未授权 → 高危；只读函数未授权 → 中危（信息泄露）
"""
import re

from .base import BaseDetector, register
from services.solc_parser import parse_source, format_params

RISK_HIGH, RISK_MID = "高危", "中危"

# 常见访问控制修饰符
ACCESS_MODIFIERS = {
    "onlyOwner", "onlyAdmin", "onlyAuthorized", "onlyAuth", "requireAuth",
    "auth", "onlyRole", "hasRole", "restricted", "onlyMinter", "onlyPauser",
    "onlyController", "onlyGovernance", "nonReentrant",
}
# 函数体内权限校验特征
BODY_CHECK_RE = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|require\s*\(\s*_?msgSender\s*\(\)\s*==|"
    r"require\s*\([^)]*(?:hasRole|checkRole|isOwner|_checkOnERC721Received)|"
    r"_msgSender\(\)\s*==")
# 系统级安全白名单（ERC20/ERC721 标准接口，本身设计为公开调用）
SAFE_FUNCTIONS = {
    "name", "symbol", "decimals", "totalSupply", "balanceOf", "allowance",
    "transfer", "approve", "transferFrom", "owner", "renounceOwnership",
    "transferOwnership", "supportsInterface", "safeTransferFrom",
    "safeMint", "setApprovalForAll", "balanceOfBatch", "isApprovedForAll",
}


@register
class AuthDetector(BaseDetector):
    """接口暴露检测插件：无权限修饰的对外函数 → 未授权访问风险"""
    name = "auth_detector"
    description = "接口暴露/权限检测（渗透测试接口探测思想）"

    def detect(self, contract_info: dict) -> list:
        source = contract_info.get("source_code") or ""
        info = contract_info.get("parse") or parse_source(source)
        vulns = []
        for fn in info.get("functions", []):
            if fn["name"] in ("constructor", "receive", "fallback"):
                continue
            if fn.get("visibility") not in ("public", "external"):
                continue
            if any(mod in ACCESS_MODIFIERS for mod in fn.get("modifiers", [])):
                continue
            if BODY_CHECK_RE.search(fn.get("body", "")):
                continue
            if fn["name"] in SAFE_FUNCTIONS and not fn.get("params"):
                continue

            is_readonly = fn.get("mutability") in ("view", "pure")
            level = RISK_MID if is_readonly else RISK_HIGH
            signature = f"{fn['name']}({format_params(fn['params'])})"
            vulns.append({
                "vul_type": "未授权访问风险",
                "risk_level": level,
                "location": f"第{fn['line']}行 {signature}",
                "description": (
                    f"对外接口 {signature} 为 {fn['visibility']} 函数，"
                    f"{'只读函数可被任意地址查询敏感数据' if is_readonly else '可被任意地址直接调用修改合约状态'}，"
                    f"未检测到访问控制修饰符或 msg.sender 权限校验，"
                    f"属于渗透测试中的'未授权访问'风险点。"
                    + (f"该函数可支付 ETH（payable）。" if fn.get("mutability") == "payable" else "")
                ),
                "suggestion": (
                    "为该函数添加访问控制：引入 onlyOwner/onlyAdmin 等修饰符，"
                    "或在函数体内校验 msg.sender 权限；"
                    "若设计上确需公开调用，请确认其对状态与资金的影响并做输入校验。"
                ),
            })
        return vulns
