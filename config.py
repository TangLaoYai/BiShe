"""全局配置

环境约定（对照项目文档）：
- 宿主机（Windows）：Flask 后端 + Vue3 前端 + MySQL 8.0
- 虚拟机（Ubuntu 20.04，桥接固定IP）：solc / Slither / FISCO BCOS 单节点
- 虚拟机相关能力当前未就绪时自动降级，接口签名不变，后续只需改本文件配置
"""
import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============== MySQL 8.0（宿主机） ==============
MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASSWORD = "123456"
MYSQL_DB = "contract_audit"

# ============== Flask ==============
SECRET_KEY = "contract-audit-system-secret-key"
HOST = "0.0.0.0"
PORT = 5000
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 上传大小限制 16MB

# 前端开发服务器地址（Vite），允许携带 Cookie 跨域
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173",
                "http://localhost:5000", "http://127.0.0.1:5000"]

# ============== 目录 ==============
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")    # 上传的 .sol 原始文件
REPORT_DIR = os.path.join(BASE_DIR, "reports")    # 审计报告输出目录

# ============== Slither（虚拟机 / WSL） ==============
# SLITHER_MODE:
#   "vm"    - 通过 SSH 调用虚拟机(桥接网络)内的 slither（文档推荐架构）
#   "wsl"   - 通过本机 WSL 发行版调用 slither
#   "local" - 直接调用宿主机 PATH 中的 slither
#   "off"   - 不调用 slither，直接使用内置规则扫描器
SLITHER_MODE = "vm"   # 虚拟机就绪后改为 "vm"

# 虚拟机桥接网络配置（SLITHER_MODE="vm" 时使用）
VM_IP = "192.168.132.100"        # 虚拟机固定IP
VM_USER = "xuniji"               # 虚拟机用户名
VM_SSH_PORT = 22
# Slither 在虚拟机内的可执行文件路径（如装在虚拟环境里就写绝对路径）
VM_SLITHER_CMD = "/home/xuniji/venv/bin/slither"
# 虚拟机内放置临时合约文件的目录（需要存在且 VM_USER 可读写）
VM_TEMP_DIR = "/home/xuniji/wsl_temp"

# WSL 配置（SLITHER_MODE="wsl" 时使用）
WSL_DISTRO = "Ubuntu-22.04"     # wsl -l -v 查看实际发行版名
WSL_USER = "tanglaoya"          # WSL 内用户名
SLITHER_TIMEOUT = 180           # slither 执行超时（秒）

# ============== solc 源码解析（虚拟机） ==============
# SOLC_MODE: "vm" 时优先调用虚拟机/WSL 内 solc 解析；解析失败自动降级内置正则解析
SOLC_MODE = "off"

# ============== FISCO BCOS 存证（虚拟机） ==============
# FISCO_SIMULATE = True：链节点未就绪时的模拟模式，接口行为与真实一致
#   （交易哈希为确定性模拟值，链上数据落地到 chain_sim.json，用于全流程联调）
# FISCO_SIMULATE = False：真实调用 FISCO BCOS Python SDK（需虚拟机节点就绪）
FISCO_SIMULATE = False
FISCO_GROUP_ID = 1
FISCO_CONTRACT_ADDRESS = "0xc6d09d57e9fd74f155fd5a77455945ed73028914"  # AuditEvidence 存证合约部署后的地址
SIM_CHAIN_FILE = os.path.join(BASE_DIR, "chain_sim.json")  # 模拟链存储文件

# AuditEvidence 存证合约 ABI（见项目文档 3.3.1）
FISCO_CONTRACT_ABI = [
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


def ensure_dirs():
    """启动时确保工作目录存在"""
    for d in [UPLOAD_DIR, REPORT_DIR]:
        os.makedirs(d, exist_ok=True)


def win_to_wsl_path(win_path: str) -> str:
    """Windows 路径转 WSL 内的 /mnt/x/... 路径，供 slither/solc 在 WSL 内读取"""
    if not win_path:
        return win_path
    p = os.path.normpath(win_path).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return p
