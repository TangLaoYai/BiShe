"""模块1：智能合约文件上传与源码解析

- 上传 .sol 合约文件，保存源码入库，自动记录上传时间（精确到分钟）
- 解析提取合约名、public/external 函数列表、参数类型
"""
import os
import re

from flask import Blueprint, request, jsonify

import config
import database
from database import Contract, User, AuditRecord
from services.solc_parser import parse_source, format_params
from utils import now_minute
from . import login_required, current_user

bp = Blueprint("contract", __name__, url_prefix="/api/contracts")


def contract_file_path(contract_id: int, contract_name: str) -> str:
    """合约源码文件落盘路径：uploads/{合约ID}_{合约名}.sol"""
    safe = re.sub(r"[^\w.-]", "_", contract_name or "contract")
    return os.path.join(config.UPLOAD_DIR, f"{contract_id}_{safe}.sol")


def save_sol_file(contract_id: int, contract_name: str, source_code: str) -> str:
    path = contract_file_path(contract_id, contract_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(source_code)
    return path


@bp.post("")
@login_required
def upload_contract():
    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify({"message": "请选择 .sol 合约文件"}), 400
    if not file.filename.lower().endswith(".sol"):
        return jsonify({"message": "仅支持 .sol 格式合约文件"}), 400

    source_code = file.read().decode("utf-8", errors="replace")
    if not source_code.strip():
        return jsonify({"message": "合约文件内容为空"}), 400

    info = parse_source(source_code)
    contract_name = (info.get("contract_name") or
                     os.path.splitext(file.filename)[0])[:100]
    function_count = len(info.get("functions", []))

    user = current_user()
    c = Contract(contract_name=contract_name, source_code=source_code,
                 user_id=user["user_id"], upload_time=now_minute(),
                 function_count=function_count)
    s = database.Session()
    try:
        s.add(c)
        s.commit()
        # 源码落盘（供 Slither/solc 读取），失败不影响入库
        try:
            save_sol_file(c.id, contract_name, source_code)
        except OSError:
            pass
        return jsonify({
            "id": c.id,
            "contract_name": c.contract_name,
            "upload_time": c.upload_time.strftime("%Y-%m-%d %H:%M"),
            "pragma": info.get("pragma", ""),
            "functions": [_fn_brief(fn) for fn in info.get("functions", [])],
        })
    finally:
        database.Session.remove()


@bp.get("")
@login_required
def list_contracts():
    """合约列表：普通用户仅看自身上传记录，管理员查看全部

    支持分页（page/page_size，默认 10，上限 50）；支持 keyword 前缀模糊搜索
    （走 contract_name 索引）；列表不再调用 parse_source，直接读预存的
    function_count 字段，避免对每条源码跑正则解析。
    """
    user = current_user()
    keyword = (request.args.get("keyword") or "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(50, max(1, int(request.args.get("page_size", 10))))
    except ValueError:
        page, page_size = 1, 10

    s = database.Session()
    try:
        q = s.query(Contract, User.username).outerjoin(User, Contract.user_id == User.id)
        if user["role"] != "admin":
            q = q.filter(Contract.user_id == user["user_id"])
        if keyword:
            # 前缀匹配，可走 ix_contract_name 索引；如需双向模糊用 %keyword%
            q = q.filter(Contract.contract_name.like(f"{keyword}%"))

        total = q.count()
        rows = (q.order_by(Contract.id.desc())
                .offset((page - 1) * page_size).limit(page_size).all())
        items = [{
            "id": c.id,
            "contract_name": c.contract_name,
            "upload_time": c.upload_time.strftime("%Y-%m-%d %H:%M"),
            "uploader": username,
            "function_count": c.function_count,
            "can_audit": user["role"] == "admin" or c.user_id == user["user_id"],
        } for c, username in rows]
        return jsonify({"total": total, "page": page, "page_size": page_size, "items": items})
    finally:
        database.Session.remove()


@bp.get("/<int:contract_id>")
@login_required
def contract_detail(contract_id: int):
    """合约详情：源码解析结果（函数列表）+ 历史审计记录"""
    user = current_user()
    s = database.Session()
    try:
        c = s.query(Contract).filter(Contract.id == contract_id).first()
        if not c:
            return jsonify({"message": "合约不存在"}), 404
        if user["role"] != "admin" and c.user_id != user["user_id"]:
            return jsonify({"message": "无权访问该合约"}), 403

        info = parse_source(c.source_code)
        audits = s.query(AuditRecord).filter(
            AuditRecord.contract_id == contract_id
        ).order_by(AuditRecord.id.desc()).all()
        return jsonify({
            "id": c.id,
            "contract_name": c.contract_name,
            "pragma": info.get("pragma", ""),
            "upload_time": c.upload_time.strftime("%Y-%m-%d %H:%M"),
            "functions": [_fn_brief(fn) for fn in info.get("functions", [])],
            "audits": [{
                "audit_id": a.audit_id,
                "audit_time": a.audit_time.strftime("%Y-%m-%d %H:%M"),
                "status": a.status,
            } for a in audits],
        })
    finally:
        database.Session.remove()


def _fn_brief(fn: dict) -> dict:
    return {
        "name": fn["name"],
        "visibility": fn["visibility"],
        "mutability": fn.get("mutability", ""),
        "modifiers": fn.get("modifiers", []),
        "params": fn.get("params", []),
        "params_text": format_params(fn.get("params", [])),
        "line": fn.get("line", 0),
    }
