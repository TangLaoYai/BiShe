"""扩展模块：审计存证上链（FISCO BCOS）

- 上链存证：用户手动触发，计算源码/审计记录 SHA256，调用存证合约，返回交易哈希
- 存证校验：重算本地哈希与链上哈希对比，验证本地数据是否被篡改
- 历史存证查询：按角色隔离展示存证记录列表，支持按哈希地址前缀搜索
"""
import json

from flask import Blueprint, request, jsonify
from sqlalchemy import or_

import database
from database import AuditRecord, Contract, Evidence, Vulnerability
from services import fisco_client
from utils import now_minute
from . import login_required, current_user

bp = Blueprint("evidence", __name__, url_prefix="/api/evidence")


def build_audit_text(audit: AuditRecord, vulns: list) -> str:
    """审计记录全文（规范化 JSON，作为存证哈希原文）"""
    return json.dumps({
        "audit_id": audit.audit_id,
        "contract_id": audit.contract_id,
        "audit_time": audit.audit_time.strftime("%Y-%m-%d %H:%M"),
        "status": audit.status,
        "vulns": [{"vul_type": v.vul_type, "risk_level": v.risk_level,
                   "location": v.location, "description": v.description,
                   "suggestion": v.suggestion} for v in vulns],
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _get_audit_with_permission(s, audit_id: str):
    """带权限校验地加载审计记录，返回 (record, error_response)"""
    user = current_user()
    record = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
    if not record:
        return None, (jsonify({"message": "审计记录不存在"}), 404)
    if user["role"] != "admin" and record.user_id != user["user_id"]:
        return None, (jsonify({"message": "无权访问该审计记录"}), 403)
    return record, None


# ===================== 上链存证 =====================

@bp.post("")
@login_required
def chain_evidence():
    """手动触发上链存证，返回交易哈希与上链时间"""
    data = request.get_json(silent=True) or {}
    audit_id = (data.get("audit_id") or "").strip()
    s = database.Session()
    try:
        record, err = _get_audit_with_permission(s, audit_id)
        if err:
            return err
        if record.status != "完成":
            return jsonify({"message": "仅审计状态为'完成'的记录可上链存证"}), 400
        exists = s.query(Evidence).filter(Evidence.audit_id == audit_id).first()
        if exists:
            return jsonify({"message": "该审计已完成上链存证",
                            "tx_hash": exists.tx_hash,
                            "chain_time": exists.chain_time.strftime("%Y-%m-%d %H:%M")}), 409

        c = s.query(Contract).filter(Contract.id == record.contract_id).first()
        vulns = (s.query(Vulnerability).filter(Vulnerability.audit_id == audit_id)
                 .order_by(Vulnerability.id.asc()).all())

        # 计算合约源码 SHA256 与审计记录全文 SHA256
        contract_hash = fisco_client.sha256_hex(c.source_code)
        audit_hash = fisco_client.sha256_hex(build_audit_text(record, vulns))

        # 调用 FISCO BCOS 存证合约 saveEvidence
        try:
            result = fisco_client.save_evidence(audit_id, contract_hash, audit_hash)
        except Exception as e:
            return jsonify({"message": f"链上存证失败：{e}"}), 500

        ev = Evidence(audit_id=audit_id, contract_hash=contract_hash,
                      audit_hash=audit_hash, tx_hash=result["tx_hash"][:66],
                      chain_time=now_minute(), user_id=current_user()["user_id"])
        s.add(ev)
        s.commit()
        return jsonify({
            "message": "上链存证成功",
            "tx_hash": ev.tx_hash,
            "chain_time": ev.chain_time.strftime("%Y-%m-%d %H:%M"),
            "contract_hash": contract_hash,
            "audit_hash": audit_hash,
        })
    finally:
        database.Session.remove()


# ===================== 存证校验 =====================

@bp.post("/verify")
@login_required
def verify_evidence():
    """存证校验：重算本地哈希与链上存储哈希对比，验证本地数据是否被篡改"""
    data = request.get_json(silent=True) or {}
    audit_id = (data.get("audit_id") or "").strip()
    s = database.Session()
    try:
        record, err = _get_audit_with_permission(s, audit_id)
        if err:
            return err
        ev = s.query(Evidence).filter(Evidence.audit_id == audit_id).first()
        if not ev:
            return jsonify({"message": "该审计尚未上链存证"}), 404

        c = s.query(Contract).filter(Contract.id == record.contract_id).first()
        vulns = (s.query(Vulnerability).filter(Vulnerability.audit_id == audit_id)
                 .order_by(Vulnerability.id.asc()).all())

        # 重算本地哈希
        local_contract_hash = fisco_client.sha256_hex(c.source_code)
        local_audit_hash = fisco_client.sha256_hex(build_audit_text(record, vulns))

        # 链上哈希（存证表为链上存证副本，getEvidence 用于真实链模式二次核对）
        chain = fisco_client.get_evidence(audit_id)
        chain_contract_hash, chain_audit_hash = ev.contract_hash, ev.audit_hash
        if chain and len(chain) >= 3 and chain[1] and chain[2]:
            chain_contract_hash, chain_audit_hash = chain[1], chain[2]

        contract_ok = local_contract_hash == chain_contract_hash
        audit_ok = local_audit_hash == chain_audit_hash
        return jsonify({
            "consistent": contract_ok and audit_ok,
            "contract_match": contract_ok,
            "audit_match": audit_ok,
            "local": {"contract_hash": local_contract_hash,
                      "audit_hash": local_audit_hash},
            "chain": {"contract_hash": chain_contract_hash,
                      "audit_hash": chain_audit_hash,
                      "tx_hash": ev.tx_hash},
        })
    finally:
        database.Session.remove()


# ===================== 历史存证查询 =====================

@bp.get("")
@login_required
def list_evidence():
    """历史存证记录列表：审计ID、合约名称、上链时间、交易哈希（按角色隔离）

    支持 hash 查询参数：对 tx_hash / contract_hash / audit_hash 任一字段做前缀匹配，
    适合用户从区块链浏览器或审计报告复制哈希片段来定位存证记录。
    """
    user = current_user()
    hash_q = (request.args.get("hash") or "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(50, max(1, int(request.args.get("page_size", 10))))
    except ValueError:
        page, page_size = 1, 10

    s = database.Session()
    try:
        q = (s.query(Evidence, Contract.contract_name)
             .join(AuditRecord, Evidence.audit_id == AuditRecord.audit_id)
             .join(Contract, AuditRecord.contract_id == Contract.id))
        if user["role"] != "admin":
            q = q.filter(Evidence.user_id == user["user_id"])
        if hash_q:
            # 前缀匹配任一哈希字段；OR 查询，存证数据通常不大可接受全表扫
            prefix = f"{hash_q}%"
            q = q.filter(or_(
                Evidence.tx_hash.like(prefix),
                Evidence.contract_hash.like(prefix),
                Evidence.audit_hash.like(prefix),
            ))

        total = q.count()
        rows = (q.order_by(Evidence.id.desc())
                .offset((page - 1) * page_size).limit(page_size).all())
        items = [{
            "audit_id": ev.audit_id,
            "contract_name": contract_name,
            "chain_time": ev.chain_time.strftime("%Y-%m-%d %H:%M"),
            "tx_hash": ev.tx_hash,
            "contract_hash": ev.contract_hash,
            "audit_hash": ev.audit_hash,
        } for ev, contract_name in rows]
        return jsonify({"total": total, "page": page, "page_size": page_size, "items": items})
    finally:
        database.Session.remove()
