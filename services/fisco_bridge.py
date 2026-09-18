"""在虚拟机上执行 FISCO 存证调用的 Python 脚本。

由宿主机 fisco_client.py 通过 ssh 调用。
虚拟机路径：~/fisco_bridge.py
"""
import json
import os
import sys
import time

# 切到 python-sdk 目录，让相对路径证书能找到
SDK_DIR = "/home/xuniji/python-sdk"
os.chdir(SDK_DIR)
sys.path.insert(0, SDK_DIR)

from client.bcosclient import BcosClient

CONTRACT_ADDRESS = "0xc6d09d57e9fd74f155fd5a77455945ed73028914"
ABI = [
    {"inputs": [{"name": "auditId", "type": "string"},
                {"name": "contractHash", "type": "string"},
                {"name": "auditRecordHash", "type": "string"}],
     "name": "saveEvidence", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"name": "auditId", "type": "string"}],
     "name": "getEvidence", "outputs": [{"name": "", "type": "string"},
                                        {"name": "", "type": "string"},
                                        {"name": "", "type": "string"},
                                        {"name": "", "type": "uint256"}],
     "stateMutability": "view", "type": "function"},
]

def main():
    action = sys.argv[1]
    client = BcosClient()

    if action == "save":
        audit_id = sys.argv[2]
        contract_hash = sys.argv[3]
        audit_hash = sys.argv[4]
        receipt = client.sendRawTransactionGetReceipt(
            CONTRACT_ADDRESS, ABI, "saveEvidence",
            [audit_id, contract_hash, audit_hash],
        )
        tx_hash = receipt.get("transactionHash", "")
        if tx_hash and not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash
        print(json.dumps({"tx_hash": tx_hash, "timestamp": int(time.time())}))
    elif action == "get":
        audit_id = sys.argv[2]
        result = client.call(CONTRACT_ADDRESS, ABI, "getEvidence", [audit_id])
        # result 可能是 tuple 或 dict
        if isinstance(result, tuple) and len(result) >= 4:
            print(json.dumps(list(result[:4])))
        elif isinstance(result, dict):
            outputs = result.get("result", [])
            if outputs and len(outputs) >= 4:
                print(json.dumps(list(outputs[:4])))
            else:
                print("null")
        else:
            print("null")
    elif action == "ping":
        print(json.dumps({"blockNumber": client.getBlockNumber()}))
    else:
        print(json.dumps({"error": f"unknown action: {action}"}))

if __name__ == "__main__":
    main()
