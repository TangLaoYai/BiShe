"""FISCO BCOS 存证合约调用封装（扩展模块：审计存证上链）

按文档 3.3.2 上链流程：
- 计算合约源码 SHA256、审计记录全文 SHA256
- 调用存证合约 saveEvidence，返回交易哈希

两种模式（config.FISCO_SIMULATE）：
- True：模拟模式，链上数据落地到 chain_sim.json，接口行为与真实一致
- False：通过 SSH 调用虚拟机上的 fisco_bridge.py（虚拟机 python-sdk 已就绪），
  避开 Windows 上 python-sdk 的版本兼容性问题
"""
import hashlib
import json
import os
import subprocess
import time

import config


def sha256_hex(text: str) -> str:
    """SHA256 哈希（合约源码/审计记录全文）"""
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


# ===================== 真实链模式（SSH 桥接虚拟机） =====================

def _bridge_call(action: str, *args):
    """通过 SSH 调用虚拟机上的 fisco_bridge.py，返回 stdout 的 JSON 解析结果"""
    arg_str = " ".join(f"'{a}'" for a in args)
    cmd = [
        "ssh", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        f"{config.VM_USER}@{config.VM_IP}",
        f"~/venv/bin/python ~/fisco_bridge.py {action} {arg_str}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=30, encoding="utf-8", errors="replace")
        out = (proc.stdout or "").strip()
        if out.startswith("{") or out.startswith("["):
            return json.loads(out)
        return None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def _sdk_save_evidence(audit_id: str, contract_hash: str, audit_hash: str) -> dict:
    """SSH 调用虚拟机 bridge 发送存证交易"""
    result = _bridge_call("save", audit_id, contract_hash, audit_hash)
    if result and result.get("tx_hash"):
        return result
    # 降级到模拟
    return _sim_save_evidence(audit_id, contract_hash, audit_hash)


def _sdk_get_evidence(audit_id: str):
    """SSH 调用虚拟机 bridge 读取链上存证"""
    result = _bridge_call("get", audit_id)
    if result is not None and result != "null":
        return result
    return None


# ===================== 模拟链模式（降级） =====================

def _sim_load() -> dict:
    if os.path.exists(config.SIM_CHAIN_FILE):
        with open(config.SIM_CHAIN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _sim_store(data: dict):
    with open(config.SIM_CHAIN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _sim_save_evidence(audit_id: str, contract_hash: str, audit_hash: str) -> dict:
    """模拟模式：确定性生成模拟交易哈希并持久化，模拟链上存储"""
    chain = _sim_load()
    if audit_id in chain:  # 幂等：同一审计只存一次
        return {"tx_hash": chain[audit_id]["txHash"],
                "timestamp": chain[audit_id]["timestamp"]}
    tx_hash = "0x" + hashlib.sha256(
        f"{audit_id}|{contract_hash}|{audit_hash}|{time.time_ns()}".encode()
    ).hexdigest()
    timestamp = int(time.time())
    chain[audit_id] = {
        "auditId": audit_id, "contractHash": contract_hash,
        "auditRecordHash": audit_hash, "txHash": tx_hash, "timestamp": timestamp,
    }
    _sim_store(chain)
    return {"tx_hash": tx_hash, "timestamp": timestamp}


def _sim_get_evidence(audit_id: str):
    chain = _sim_load()
    e = chain.get(audit_id)
    if not e:
        return None
    return [e["auditId"], e["contractHash"], e["auditRecordHash"], e["timestamp"]]


# ===================== 对外统一接口 =====================

def save_evidence(audit_id: str, contract_hash: str, audit_hash: str) -> dict:
    """调用存证合约 saveEvidence，返回 {tx_hash, timestamp}"""
    if config.FISCO_SIMULATE:
        return _sim_save_evidence(audit_id, contract_hash, audit_hash)
    return _sdk_save_evidence(audit_id, contract_hash, audit_hash)


def get_evidence(audit_id: str):
    """读取链上存证 getEvidence，返回 [auditId, contractHash, auditRecordHash, timestamp] 或 None"""
    if config.FISCO_SIMULATE:
        return _sim_get_evidence(audit_id)
    return _sdk_get_evidence(audit_id)
