"""底层支撑：用户注册 / 登录 / 会话管理（不计入6大业务模块）

- 注册：密码 MD5 加密后写入 user 表
- 登录：校验账号与 MD5 密码，生成 Session
"""
import re

from flask import Blueprint, request, jsonify, session

import database
from database import User
from utils import md5, now_minute
from . import current_user

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_RE = re.compile(r"^[\w\u4e00-\u9fa5-]{3,50}$")


@bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not USERNAME_RE.match(username):
        return jsonify({"message": "账号需为3-50位字母、数字、下划线或中文"}), 400
    if len(password) < 6:
        return jsonify({"message": "密码长度至少6位"}), 400

    s = database.Session()
    try:
        if s.query(User).filter(User.username == username).first():
            return jsonify({"message": "该账号已被注册"}), 400
        user = User(username=username, password_md5=md5(password),
                    role="user", create_time=now_minute())
        s.add(user)
        s.commit()
        return jsonify({"message": "注册成功，请登录", "id": user.id})
    finally:
        database.Session.remove()


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    s = database.Session()
    try:
        user = s.query(User).filter(User.username == username).first()
        if not user or user.password_md5 != md5(password):
            return jsonify({"message": "账号或密码错误"}), 400
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role
        session.permanent = True
        return jsonify({"message": "登录成功", "user": current_user()})
    finally:
        database.Session.remove()


@bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"message": "已退出登录"})


@bp.get("/me")
def me():
    if not session.get("user_id"):
        return jsonify({"message": "未登录"}), 401
    return jsonify(current_user())
