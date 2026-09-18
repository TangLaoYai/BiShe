"""通用工具：MD5 加密、分钟级时间、审计编号生成"""
import hashlib
import uuid
from datetime import datetime


def md5(text: str) -> str:
    """密码 MD5 加密（项目约定：密码统一 MD5 后存储）"""
    return hashlib.md5(str(text).encode("utf-8")).hexdigest()


def now_minute() -> datetime:
    """当前时间，精确到分钟（项目约定：所有时间字段精确到分钟）"""
    return datetime.now().replace(second=0, microsecond=0)


def gen_audit_id() -> str:
    """生成审计任务唯一编号：AUD + 年月日时分秒 + 8位随机串"""
    return f"AUD{datetime.now().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:8].upper()}"
