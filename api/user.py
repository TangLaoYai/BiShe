"""扩展模块：用户管理（仅管理员）

- 用户列表：查看所有账号（用户名/角色/状态/创建时间）
- 禁用/启用账号：soft toggle，不删除任何记录
- 不提供新增/删除/改角色/改密码接口（保持最小变更，符合"无删除"约定）
"""
from flask import Blueprint, request, jsonify
from sqlalchemy import func

import database
from database import User, Contract, AuditRecord
from . import admin_required

bp = Blueprint("user", __name__, url_prefix="/api/users")


@bp.get("")
@admin_required
def list_users():
    """用户列表（仅管理员），附带每用户的合约数/审计数统计"""
    s = database.Session()
    try:
        rows = s.query(User).order_by(User.id.asc()).all()
        if not rows:
            return jsonify({"total": 0, "items": []})

        # 批量统计，避免 N+1
        uid_list = [u.id for u in rows]
        contract_counts = dict(
            s.query(Contract.user_id, func.count(Contract.id))
            .filter(Contract.user_id.in_(uid_list))
            .group_by(Contract.user_id).all()
        )
        audit_counts = dict(
            s.query(AuditRecord.user_id, func.count(AuditRecord.id))
            .filter(AuditRecord.user_id.in_(uid_list))
            .group_by(AuditRecord.user_id).all()
        )

        items = [{
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "status": getattr(u, "status", "active"),
            "create_time": u.create_time.strftime("%Y-%m-%d %H:%M"),
            "contract_count": contract_counts.get(u.id, 0),
            "audit_count": audit_counts.get(u.id, 0),
        } for u in rows]
        return jsonify({"total": len(items), "items": items})
    finally:
        database.Session.remove()


@bp.post("/<int:user_id>/toggle-status")
@admin_required
def toggle_status(user_id):
    """切换账号状态：active ↔ disabled（仅管理员）

    防呆：不允许管理员禁用自己，避免误操作把自己锁出去。
    """
    from flask import session
    if session.get("user_id") == user_id:
        return jsonify({"message": "不允许禁用自己的账号"}), 400

    s = database.Session()
    try:
        user = s.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"message": "用户不存在"}), 404

        current = getattr(user, "status", "active")
        new_status = "disabled" if current == "active" else "active"
        user.status = new_status
        s.commit()
        return jsonify({
            "message": f"账号已{'禁用' if new_status == 'disabled' else '启用'}",
            "id": user.id,
            "status": new_status,
        })
    finally:
        database.Session.remove()
