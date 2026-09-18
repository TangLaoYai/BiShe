"""模块2：静态漏洞扫描 —— SlitherDetector

按文档调用方式：`slither contract.sol --json -`
- SLITHER_MODE="vm"：通过 SSH 调用虚拟机(桥接网络)内的 slither（文档推荐架构）
- SLITHER_MODE="wsl"：通过本机 WSL 发行版调用 slither
- SLITHER_MODE="local"：直接调用宿主机 PATH 中的 slither
- SLITHER_MODE="off"：跳过 Slither
调用失败/超时/未安装时自动降级为内置规则扫描器（BuiltinScannerDetector）。
解析 Slither JSON 中的 impact / description / elements 字段，映射三级风险后入库。
"""
import json
import os
import subprocess

import config
from .base import BaseDetector, register
from .builtin_scanner import BuiltinScannerDetector

IMPACT_MAP = {"High": "高危", "Medium": "中危", "Low": "低危",
              "Informational": "低危", "Optimization": "低危"}

CHECK_NAME_MAP = {
    "reentrancy-eth": "重入漏洞", "reentrancy-no-eth": "重入漏洞",
    "reentrancy-unlimited-gas": "重入漏洞", "reentrancy-benign": "重入漏洞",
    "arbitrary-send-eth": "任意转账", "arbitrary-send": "任意转账",
    "arbitrary-send-erc20": "任意转账",
    "tx-origin": "tx.origin鉴权缺陷", "delegatecall": "危险delegatecall",
    "suicidal": "任意自毁", "unchecked-lowlevel": "未检查底层调用返回值",
    "unchecked-transfer": "未检查转账返回值", "integer-overflow": "整数溢出",
    "underflow": "整数下溢", "weak-randomness": "弱随机数",
    "timestamp-dependence": "时间戳依赖", "block-timestamp": "时间戳依赖",
    "unprotected-upgrade": "未受保护的可升级", "calls-loop": "循环外部调用",
    "shadowing-state": "状态变量遮蔽", "unprotected-selfdestruct": "任意自毁",
}

CHECK_SUGGESTION_MAP = {
    "reentrancy-eth": "遵循 Checks-Effects-Interactions 模式，先更新状态再转账，并加入 nonReentrant 保护。",
    "arbitrary-send-eth": "对转账目标与入口函数添加 onlyOwner 等权限校验。",
    "tx-origin": "使用 msg.sender 替代 tx.origin 鉴权。",
    "delegatecall": "固定 delegatecall 目标，避免用户可控地址。",
    "suicidal": "为 selfdestruct 添加强权限校验。",
    "unchecked-lowlevel": "检查 call/send 返回值并用 require 断言。",
    "integer-overflow": "升级编译器至 ^0.8.0 或使用 SafeMath。",
    "underflow": "升级编译器至 ^0.8.0 或使用 SafeMath。",
}


def _build_cmd(sol_path: str, wsl_path: str) -> list:
    if config.SLITHER_MODE == "wsl":
        return ["wsl", "-d", config.WSL_DISTRO, "bash", "-lc",
                f"slither '{wsl_path}' --json -"]
    if config.SLITHER_MODE == "local":
        return ["slither", sol_path, "--json", "-"]
    if config.SLITHER_MODE == "vm":
        return None  # vm 模式走 _run_vm_slither
    return None


def _run_vm_slither(sol_path: str):
    """虚拟机模式：SCP 上传合约到虚拟机，SSH 执行 slither，返回 JSON detectors 列表

    流程：scp 合约到 VM_TEMP_DIR → ssh 执行 slither → 解析 stdout JSON
    任何步骤失败返回 None（交由降级逻辑）。
    """
    import uuid
    remote_name = f"{uuid.uuid4().hex}.sol"
    remote_path = f"{config.VM_TEMP_DIR.rstrip('/')}/{remote_name}"

    # 1. 上传合约文件到虚拟机
    scp = subprocess.run(
        ["scp", "-P", str(config.VM_SSH_PORT), "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=NUL",
         sol_path, f"{config.VM_USER}@{config.VM_IP}:{remote_path}"],
        capture_output=True, text=True, timeout=60)
    if scp.returncode != 0:
        return None

    # 2. SSH 执行 slither（直接让 ssh 远程执行，不用 bash -c，避免 source 报错）
    cmd = (f"source /home/{config.VM_USER}/venv/bin/activate && "
           f"SOLC_VERSION=0.8.0 {config.VM_SLITHER_CMD} {remote_path} --json -; "
           f"rm -f {remote_path}")
    ssh = subprocess.run(
        ["ssh", "-p", str(config.VM_SSH_PORT), "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=NUL",
         f"{config.VM_USER}@{config.VM_IP}", cmd],
        capture_output=True, text=True, timeout=config.SLITHER_TIMEOUT,
        encoding="utf-8", errors="replace")

    # 解析：slither 检出漏洞时退出码非 0，以 stdout 可解析为准
    for text in (ssh.stdout, ssh.stderr):
        text = (text or "").strip()
        if not text.startswith("{"):
            continue
        try:
            data = json.loads(text)
            return data.get("results", {}).get("detectors", []) or data.get("detectors", [])
        except ValueError:
            continue
    return None


def _run_slither_json(sol_path: str):
    """执行 slither 并解析 JSON 输出，任何失败返回 None（交由降级逻辑）"""
    if config.SLITHER_MODE == "vm":
        return _run_vm_slither(sol_path)
    cmd = _build_cmd(sol_path, config.win_to_wsl_path(sol_path))
    if not cmd:
        return None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=config.SLITHER_TIMEOUT, encoding="utf-8",
                              errors="replace")
        # 注意：slither 检出漏洞时退出码非 0，因此只以 stdout 可解析为准
        for text in (proc.stdout, proc.stderr):
            text = (text or "").strip()
            if not text.startswith("{"):
                continue
            try:
                data = json.loads(text)
            except ValueError:
                continue
            return data.get("results", {}).get("detectors", []) or data.get("detectors", [])
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    return None


def _location_of(element_list) -> str:
    for el in element_list or []:
        sm = el.get("source_mapping") or {}
        lines = sm.get("lines") or []
        if lines:
            fn = el.get("name") or el.get("type") or ""
            return f"第{lines[0]}行 {fn}" if fn else f"第{lines[0]}行"
    return "全局"


@register
class SlitherDetector(BaseDetector):
    """静态漏洞扫描插件：优先 Slither，不可用自动降级内置规则扫描"""
    name = "slither"
    description = "Slither 静态漏洞扫描（降级：内置规则扫描）"

    def detect(self, contract_info: dict) -> list:
        sol_path = contract_info.get("file_path")
        if config.SLITHER_MODE != "off" and sol_path:
            detectors = _run_slither_json(sol_path)
            if detectors is not None:
                return self._parse(detectors)
        # 降级：内置规则扫描器
        return BuiltinScannerDetector().detect(contract_info)

    def _parse(self, detectors: list) -> list:
        vulns = []
        for item in detectors:
            impact = item.get("impact", "Low")
            check = item.get("check", "unknown")
            vulns.append({
                "vul_type": CHECK_NAME_MAP.get(check, check),
                "risk_level": IMPACT_MAP.get(impact, "低危"),
                "location": _location_of(item.get("elements")),
                "description": (item.get("description") or "").strip()[:2000],
                "suggestion": CHECK_SUGGESTION_MAP.get(
                    check, "参考漏洞描述与 Slither 官方文档修复该问题。"),
            })
        return vulns
