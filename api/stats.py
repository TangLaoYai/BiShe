"""扩展模块：仪表盘数据聚合（登录后可见，管理员看全局，普通用户看自己）

一次请求返回仪表盘所需的全部数据：
- cards：6 个数字卡片（合约/审计/进行中/高危漏洞/存证/用户）
- trend：近 7 天每日审计数 [{date, count}]
- risk_pie：漏洞等级分布 [{name, value}]
- top_vulns：Top5 漏洞类型 [{name, value}]
"""
from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from sqlalchemy import func

import database
from database import User, Contract, AuditRecord, Vulnerability, Evidence
from . import login_required, current_user

bp = Blueprint("stats", __name__, url_prefix="/api/stats")


@bp.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    is_admin = user["role"] == "admin"

    s = database.Session()
    try:
        # ---- 1. 数字卡片 ----
        contract_q = s.query(Contract)
        audit_q = s.query(AuditRecord)
        running_q = s.query(AuditRecord).filter(AuditRecord.status == "running")
        high_vuln_q = s.query(Vulnerability).filter(Vulnerability.risk_level == "高危")
        evidence_q = s.query(Evidence)

        if not is_admin:
            contract_q = contract_q.filter(Contract.user_id == user["user_id"])
            audit_q = audit_q.filter(AuditRecord.user_id == user["user_id"])
            running_q = running_q.filter(AuditRecord.user_id == user["user_id"])
            # 漏洞/存证按 audit_id 关联用户：通过子查询过滤
            user_audit_ids = s.query(AuditRecord.audit_id).filter(
                AuditRecord.user_id == user["user_id"]).subquery()
            high_vuln_q = high_vuln_q.filter(Vulnerability.audit_id.in_(user_audit_ids))
            evidence_q = evidence_q.filter(Evidence.user_id == user["user_id"])

        cards = {
            "contracts": contract_q.count(),
            "audits": audit_q.count(),
            "running": running_q.count(),
            "high_vulns": high_vuln_q.count(),
            "evidence": evidence_q.count(),
            "users": s.query(User).count() if is_admin else None,  # 普通用户不显示用户数
        }

        # ---- 2. 近 7 天趋势 ----
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        days = [today - timedelta(days=6 - i) for i in range(7)]
        day_labels = [d.strftime("%m-%d") for d in days]

        audit_q7 = s.query(AuditRecord)
        if not is_admin:
            audit_q7 = audit_q7.filter(AuditRecord.user_id == user["user_id"])
        # 用 audit_time 的日期分组
        rows = (audit_q7
                .with_entities(
                    func.date(AuditRecord.audit_time).label("d"),
                    func.count(AuditRecord.id).label("c"))
                .filter(AuditRecord.audit_time >= days[0])
                .group_by(func.date(AuditRecord.audit_time)).all())
        count_map = {str(r.d): r.c for r in rows}
        trend = [{"date": label, "count": count_map.get(days[i].strftime("%Y-%m-%d"), 0)}
                 for i, label in enumerate(day_labels)]

        # ---- 3. 漏洞等级饼图 ----
        vuln_q = s.query(Vulnerability)
        if not is_admin:
            vuln_q = vuln_q.filter(Vulnerability.audit_id.in_(user_audit_ids))
        risk_rows = (vuln_q
                     .with_entities(Vulnerability.risk_level, func.count(Vulnerability.id))
                     .group_by(Vulnerability.risk_level).all())
        risk_pie = [{"name": r[0], "value": r[1]} for r in risk_rows]

        # ---- 4. Top5 漏洞类型 ----
        top_rows = (vuln_q
                    .with_entities(Vulnerability.vul_type, func.count(Vulnerability.id).label("c"))
                    .group_by(Vulnerability.vul_type)
                    .order_by(func.count(Vulnerability.id).desc())
                    .limit(5).all())
        top_vulns = [{"name": r[0], "value": r[1]} for r in top_rows]

        return jsonify({
            "cards": cards,
            "trend": trend,
            "risk_pie": risk_pie,
            "top_vulns": top_vulns,
        })
    finally:
        database.Session.remove()
