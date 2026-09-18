"""API 包：蓝图注册 + 全局权限装饰器

权限约定（项目文档 3.1.2 全局权限控制）：
- 后端接口统一拦截，校验登录状态与角色
- 普通用户查询时自动追加 user_id = 当前用户 条件
- 系统不提供任何删除接口（所有角色均不可删除任何合约、审计、存证记录）
"""
from functools import wraps

from flask import session, jsonify


def current_user() -> dict:
    return {"user_id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role")}


def login_required(fn):
    """登录校验：未登录返回 401"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"message": "未登录或会话已过期，请重新登录"}), 401
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    """管理员校验：非管理员返回 403"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"message": "未登录或会话已过期，请重新登录"}), 401
        if session.get("role") != "admin":
            return jsonify({"message": "需要管理员权限"}), 403
        return fn(*args, **kwargs)
    return wrapper


def register_blueprints(app):
    from .auth import bp as auth_bp
    from .contract import bp as contract_bp
    from .audit import bp as audit_bp
    from .evidence import bp as evidence_bp
    from .user import bp as user_bp
    from .stats import bp as stats_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(contract_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(stats_bp)
