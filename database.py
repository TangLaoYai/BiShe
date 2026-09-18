"""数据库层：MySQL 8.0，共 5 张表（user / contract / audit_record / vulnerability / evidence）

约定：
- 所有角色均不可删除任何合约、审计、存证记录（系统不提供任何删除接口）
- 时间字段精确到分钟
- 密码 MD5 存储
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, create_engine, Index
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

import config
from utils import md5, now_minute

Base = declarative_base()


def _url(with_db: bool = False) -> str:
    pwd = config.MYSQL_PASSWORD
    base = f"mysql+pymysql://{config.MYSQL_USER}:{pwd}@{config.MYSQL_HOST}:{config.MYSQL_PORT}"
    if with_db:
        base += f"/{config.MYSQL_DB}"
    return base + "?charset=utf8mb4"


# ===================== 模型定义 =====================

class User(Base):
    """用户表"""
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, comment="账号")
    password_md5 = Column(String(32), nullable=False, comment="MD5加密密码")
    role = Column(String(20), nullable=False, default="user", comment="角色：admin/user")
    create_time = Column(DateTime, nullable=False, comment="创建时间")
    status = Column(String(20), nullable=False, default="active", comment="账号状态：active/disabled")


class Contract(Base):
    """合约源码表"""
    __tablename__ = "contract"
    __table_args__ = (
        Index("ix_contract_user_id", "user_id"),
        Index("ix_contract_name", "contract_name"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    contract_name = Column(String(100), nullable=False, comment="合约名称")
    source_code = Column(Text, nullable=False, comment=".sol源码内容")
    user_id = Column(Integer, nullable=False, comment="上传用户ID")
    upload_time = Column(DateTime, nullable=False, comment="上传时间，精确到分钟")
    function_count = Column(Integer, nullable=False, default=0, comment="public/external函数数量（上传时预存）")


class AuditRecord(Base):
    """审计记录表"""
    __tablename__ = "audit_record"
    __table_args__ = (
        Index("ix_audit_user_id", "user_id"),
        Index("ix_audit_contract_id", "contract_id"),
        Index("ix_audit_audit_time", "audit_time"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), unique=True, nullable=False, comment="审计任务唯一编号")
    contract_id = Column(Integer, nullable=False, comment="关联合约ID")
    user_id = Column(Integer, nullable=False, comment="执行用户ID")
    audit_time = Column(DateTime, nullable=False, comment="审计时间")
    status = Column(String(20), nullable=False, default="running", comment="状态：running/完成/失败")


class Vulnerability(Base):
    """漏洞详情表"""
    __tablename__ = "vulnerability"
    __table_args__ = (
        Index("ix_vul_audit_id", "audit_id"),
        Index("ix_vul_risk_level", "risk_level"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), nullable=False, comment="关联审计ID")
    vul_type = Column(String(50), nullable=False, comment="漏洞类型")
    risk_level = Column(String(20), nullable=False, comment="风险等级：高危/中危/低危")
    location = Column(String(200), nullable=False, comment="漏洞位置（行号/函数名）")
    description = Column(Text, comment="漏洞描述")
    suggestion = Column(Text, comment="修复建议")


class Evidence(Base):
    """存证记录表"""
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_ev_audit_id", "audit_id"),
        Index("ix_ev_user_id", "user_id"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), nullable=False, comment="关联审计ID")
    contract_hash = Column(String(64), nullable=False, comment="合约源码SHA256")
    audit_hash = Column(String(64), nullable=False, comment="审计记录SHA256")
    tx_hash = Column(String(66), nullable=False, comment="链上交易哈希")
    chain_time = Column(DateTime, nullable=False, comment="上链时间")
    user_id = Column(Integer, nullable=False, comment="存证用户ID")


# ===================== 初始化 =====================

engine = None
Session = None


def init_db():
    """建库（不存在时自动创建）、建表、初始化管理员账号 admin/123456

    已存在的表会通过 _migrate 兼容性升级：补充新列与新索引（IF NOT EXISTS 语义）。
    """
    global engine, Session
    # 先连接服务器创建数据库
    tmp = create_engine(_url(with_db=False))
    with tmp.connect() as conn:
        conn.exec_driver_sql(
            f"CREATE DATABASE IF NOT EXISTS {config.MYSQL_DB} "
            f"DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
        )
    tmp.dispose()

    engine = create_engine(_url(with_db=True), pool_pre_ping=True, pool_recycle=3600)
    Base.metadata.create_all(engine)
    _migrate(engine)  # 对已存在的表补齐新列与新索引
    Session = scoped_session(sessionmaker(bind=engine))

    # 初始化管理员
    s = Session()
    try:
        if not s.query(User).filter(User.username == "admin").first():
            s.add(User(username="admin", password_md5=md5("123456"),
                       role="admin", create_time=now_minute()))
            s.commit()
    finally:
        s.close()


def _migrate(eng):
    """对已存在的旧表进行兼容性升级：补充新列、补充新索引（重复创建时静默忽略）

    涵盖方案D新增的：
    - contract.function_count 列
    - contract.user_id / contract_name 索引
    - audit_record.user_id / contract_id / audit_time 索引
    - vulnerability.audit_id / risk_level 索引
    - evidence.audit_id / user_id 索引
    - user.status 列（账号禁用/启用功能）
    """
    # 列：MySQL 错误码 1060 表示重复列名，静默跳过
    alter_columns = [
        "ALTER TABLE contract ADD COLUMN function_count INT NOT NULL DEFAULT 0 "
        "COMMENT 'public/external函数数量（上传时预存）'",
        "ALTER TABLE user ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active' "
        "COMMENT '账号状态：active/disabled'",
    ]
    # 索引：MySQL 错误码 1061 表示重复键名，静默跳过
    create_indexes = [
        "CREATE INDEX ix_contract_user_id ON contract (user_id)",
        "CREATE INDEX ix_contract_name ON contract (contract_name)",
        "CREATE INDEX ix_audit_user_id ON audit_record (user_id)",
        "CREATE INDEX ix_audit_contract_id ON audit_record (contract_id)",
        "CREATE INDEX ix_audit_audit_time ON audit_record (audit_time)",
        "CREATE INDEX ix_vul_audit_id ON vulnerability (audit_id)",
        "CREATE INDEX ix_vul_risk_level ON vulnerability (risk_level)",
        "CREATE INDEX ix_ev_audit_id ON evidence (audit_id)",
        "CREATE INDEX ix_ev_user_id ON evidence (user_id)",
    ]
    with eng.connect() as conn:
        for sql in alter_columns:
            try:
                conn.exec_driver_sql(sql)
                conn.commit()
            except Exception as e:
                # 1060 = 重复列名，正常忽略；其他错误也忽略以保持启动健壮
                conn.rollback()
                if "1060" not in str(e) and "Duplicate column" not in str(e):
                    print(f"[migrate] 列升级跳过: {e}")
        for sql in create_indexes:
            try:
                conn.exec_driver_sql(sql)
                conn.commit()
            except Exception as e:
                # 1061 = 重复键名，正常忽略
                conn.rollback()
                if "1061" not in str(e) and "Duplicate key" not in str(e):
                    print(f"[migrate] 索引升级跳过: {e}")
