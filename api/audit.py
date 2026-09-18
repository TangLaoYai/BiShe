"""模块2+3+4+6：审计执行编排、漏洞入库、审计记录多条件查询、报告下载"""
import os
import threading
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify, send_file
from sqlalchemy import func

import config
import database
from database import Contract, AuditRecord, Vulnerability, User, Evidence
from detectors import get_detectors
from services.solc_parser import parse_source
from services.reports import get_report_generator
from utils import now_minute
from . import login_required, current_user
from .contract import contract_file_path, save_sol_file

bp = Blueprint("audit", __name__, url_prefix="/api/audits")


# ===================== 发起审计 =====================

@bp.post("")
@login_required
def create_audit():
    """对指定合约发起审计（异步执行，返回审计编号供轮询）"""
    data = request.get_json(silent=True) or {}
    contract_id = data.get("contract_id")
    user = current_user()

    s = database.Session()
    try:
        c = s.query(Contract).filter(Contract.id == contract_id).first()
        if not c:
            return jsonify({"message": "合约不存在"}), 404
        if user["role"] != "admin" and c.user_id != user["user_id"]:
            return jsonify({"message": "无权审计该合约"}), 403

        from utils import gen_audit_id
        record = AuditRecord(audit_id=gen_audit_id(), contract_id=c.id,
                             user_id=user["user_id"], audit_time=now_minute(),
                             status="running")
        s.add(record)
        s.commit()
        audit_id = record.audit_id
    finally:
        database.Session.remove()

    threading.Thread(target=_run_audit, args=(audit_id,), daemon=True).start()
    return jsonify({"audit_id": audit_id, "status": "running"})


def _run_audit(audit_id: str):
    """审计后台执行：遍历全部已注册检测器插件（插件化架构，单一插件异常不阻塞整体）"""
    database.Session()  # 新线程绑定独立会话
    s = database.Session()
    try:
        record = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
        if not record:
            return
        c = s.query(Contract).filter(Contract.id == record.contract_id).first()
        if not c:
            record.status = "失败"
            record.error = "合约不存在"
            s.commit()
            return

        # 源码落盘（供 Slither/虚拟机工具读取），丢失则重建
        sol_path = contract_file_path(c.id, c.contract_name)
        if not os.path.exists(sol_path):
            sol_path = save_sol_file(c.id, c.contract_name, c.source_code)

        contract_info = {
            "contract_id": c.id,
            "contract_name": c.contract_name,
            "source_code": c.source_code,
            "file_path": sol_path,
            "parse": parse_source(c.source_code),
        }

        # 遍历注册器内全部检测器插件，汇总结果
        all_vulns, module_errors = [], []
        for detector in get_detectors():
            try:
                all_vulns.extend(detector.detect(contract_info))
            except Exception:
                module_errors.append(f"{detector.name}: {traceback.format_exc(limit=1)[:200]}")

        for v in all_vulns:
            s.add(Vulnerability(audit_id=audit_id, vul_type=v["vul_type"][:50],
                                risk_level=v["risk_level"], location=v["location"][:200],
                                description=v.get("description", ""),
                                suggestion=v.get("suggestion", "")))
        s.flush()

        # 漏洞分级统计
        counts = {"高危": 0, "中危": 0, "低危": 0}
        for v in all_vulns:
            counts[v["risk_level"]] = counts.get(v["risk_level"], 0) + 1

        # 自动生成 TXT 审计报告（策略模式）
        try:
            get_report_generator("txt").generate({
                "audit_id": audit_id,
                "contract_name": c.contract_name,
                "source_code": c.source_code,
                "audit_time": record.audit_time.strftime("%Y-%m-%d %H:%M"),
                "status": "完成",
                "vulns": all_vulns,
                "counts": counts,
            })
        except Exception:
            module_errors.append(f"report: {traceback.format_exc(limit=1)[:200]}")

        # 状态：有结果即完成；全部插件失败且无结果判失败
        if not all_vulns and module_errors:
            record.status = "失败"
        else:
            record.status = "完成"
        s.commit()
    except Exception:
        try:
            r = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
            if r:
                r.status = "失败"
                s.commit()
        except Exception:
            pass
    finally:
        database.Session.remove()


# ===================== 审计记录查询（模块6） =====================

def _parse_time(val):
    """时间检索：支持到分钟（YYYY-MM-DD HH:MM）"""
    if not val:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            continue
    return None


@bp.get("")
@login_required
def list_audits():
    """多条件查询：风险等级筛选、合约名称模糊搜索、审计编号查询、时间检索（精确到分钟）、分页

    权限隔离：普通用户仅查看自身记录，管理员查看全部。
    新增 audit_id 参数：前缀匹配（走 audit_id 唯一索引），用户输入编号前几位即可定位。
    """
    user = current_user()
    keyword = (request.args.get("keyword") or "").strip()
    audit_id_q = (request.args.get("audit_id") or "").strip()
    level = (request.args.get("level") or "").strip()
    start_time = _parse_time(request.args.get("start_time"))
    end_time = _parse_time(request.args.get("end_time"))
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(50, max(1, int(request.args.get("page_size", 10))))
    except ValueError:
        page, page_size = 1, 10

    s = database.Session()
    try:
        q = s.query(AuditRecord, Contract.contract_name, User.username).join(
            Contract, AuditRecord.contract_id == Contract.id).outerjoin(
            User, AuditRecord.user_id == User.id)
        if user["role"] != "admin":
            q = q.filter(AuditRecord.user_id == user["user_id"])
        if audit_id_q:
            # 前缀匹配，走 audit_id 唯一索引
            q = q.filter(AuditRecord.audit_id.like(f"{audit_id_q}%"))
        if keyword:
            # 前缀匹配，可走 ix_contract_name 索引（双向模糊 %keyword% 会全表扫）
            q = q.filter(Contract.contract_name.like(f"{keyword}%"))
        if level:
            q = q.filter(AuditRecord.audit_id.in_(
                s.query(Vulnerability.audit_id).filter(Vulnerability.risk_level == level)))
        if start_time:
            q = q.filter(AuditRecord.audit_time >= start_time)
        if end_time:
            q = q.filter(AuditRecord.audit_time <= end_time)

        total = q.count()
        rows = (q.order_by(AuditRecord.id.desc())
                .offset((page - 1) * page_size).limit(page_size).all())

        # 批量统计本页各审计的漏洞等级数量
        audit_ids = [r[0].audit_id for r in rows]
        count_map = {}
        if audit_ids:
            stat = (s.query(Vulnerability.audit_id, Vulnerability.risk_level,
                            func.count(Vulnerability.id))
                    .filter(Vulnerability.audit_id.in_(audit_ids))
                    .group_by(Vulnerability.audit_id, Vulnerability.risk_level).all())
            for aid, lv, n in stat:
                count_map.setdefault(aid, {"高危": 0, "中危": 0, "低危": 0})[lv] = n

        items = [{
            "audit_id": r.audit_id,
            "contract_id": r.contract_id,
            "contract_name": contract_name,
            "audit_time": r.audit_time.strftime("%Y-%m-%d %H:%M"),
            "status": r.status,
            "high": count_map.get(r.audit_id, {}).get("高危", 0),
            "medium": count_map.get(r.audit_id, {}).get("中危", 0),
            "low": count_map.get(r.audit_id, {}).get("低危", 0),
            "uploader": username,
        } for r, contract_name, username in rows]
        return jsonify({"total": total, "page": page, "page_size": page_size, "items": items})
    finally:
        database.Session.remove()


# ===================== 审计详情 =====================

@bp.get("/<audit_id>")
@login_required
def audit_detail(audit_id: str):
    """审计详情：合约基础信息 + 漏洞分页列表 + 存证信息

    漏洞支持分页参数（vuln_page/vuln_page_size，默认 1/20，上限 100），
    避免单次审计漏洞过多时一次拉取全部 Text 字段（description/suggestion）。
    """
    user = current_user()
    try:
        vuln_page = max(1, int(request.args.get("vuln_page", 1)))
        vuln_page_size = min(100, max(1, int(request.args.get("vuln_page_size", 20))))
    except ValueError:
        vuln_page, vuln_page_size = 1, 20

    s = database.Session()
    try:
        r = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
        if not r:
            return jsonify({"message": "审计记录不存在"}), 404
        c = s.query(Contract).filter(Contract.id == r.contract_id).first()
        if user["role"] != "admin" and r.user_id != user["user_id"]:
            return jsonify({"message": "无权访问该审计记录"}), 403

        # 漏洞总数 + 分页（走 ix_vul_audit_id 索引）
        vuln_total = (s.query(Vulnerability)
                      .filter(Vulnerability.audit_id == audit_id).count())
        vulns = (s.query(Vulnerability).filter(Vulnerability.audit_id == audit_id)
                 .order_by(Vulnerability.id.asc())
                 .offset((vuln_page - 1) * vuln_page_size).limit(vuln_page_size).all())

        # 漏洞分级统计：仅按等级聚合，避免拉取全部行到内存
        stat = (s.query(Vulnerability.risk_level, func.count(Vulnerability.id))
                .filter(Vulnerability.audit_id == audit_id)
                .group_by(Vulnerability.risk_level).all())
        counts = {"高危": 0, "中危": 0, "低危": 0}
        for lv, n in stat:
            counts[lv] = counts.get(lv, 0) + n

        ev = s.query(Evidence).filter(Evidence.audit_id == audit_id).first()
        return jsonify({
            "audit_id": r.audit_id,
            "status": r.status,
            "audit_time": r.audit_time.strftime("%Y-%m-%d %H:%M"),
            "contract": {
                "id": c.id, "contract_name": c.contract_name,
                "upload_time": c.upload_time.strftime("%Y-%m-%d %H:%M"),
                "source_code": c.source_code,
            },
            "counts": counts,
            "vulns": {
                "total": vuln_total,
                "page": vuln_page,
                "page_size": vuln_page_size,
                "items": [{
                    "id": v.id, "vul_type": v.vul_type, "risk_level": v.risk_level,
                    "location": v.location, "description": v.description,
                    "suggestion": v.suggestion,
                } for v in vulns],
            },
            "evidence": ({
                "tx_hash": ev.tx_hash,
                "chain_time": ev.chain_time.strftime("%Y-%m-%d %H:%M"),
                "contract_hash": ev.contract_hash,
                "audit_hash": ev.audit_hash,
            } if ev else None),
        })
    finally:
        database.Session.remove()


# ===================== 审计报告下载（模块5） =====================

@bp.get("/<audit_id>/report")
@login_required
def download_report(audit_id: str):
    """下载 TXT 审计报告；不存在时按需重新生成

    启用 conditional 响应（ETag/Last-Modified），客户端有缓存时直接返回 304，
    避免重复传输整份报告。send_file 本身就是分块流式写回，不会一次性载入内存。
    """
    user = current_user()
    s = database.Session()
    try:
        r = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
        if not r:
            return jsonify({"message": "审计记录不存在"}), 404
        if user["role"] != "admin" and r.user_id != user["user_id"]:
            return jsonify({"message": "无权访问该审计记录"}), 403
        c = s.query(Contract).filter(Contract.id == r.contract_id).first()
        vulns = (s.query(Vulnerability).filter(Vulnerability.audit_id == audit_id)
                 .order_by(Vulnerability.id.asc()).all())
    finally:
        database.Session.remove()

    path = os.path.join(config.REPORT_DIR, f"{audit_id}.txt")
    if not os.path.exists(path):
        counts = {"高危": 0, "中危": 0, "低危": 0}
        for v in vulns:
            counts[v.risk_level] = counts.get(v.risk_level, 0) + 1
        get_report_generator("txt").generate({
            "audit_id": audit_id,
            "contract_name": c.contract_name,
            "source_code": c.source_code,
            "audit_time": r.audit_time.strftime("%Y-%m-%d %H:%M"),
            "status": r.status,
            "vulns": [{
                "vul_type": v.vul_type, "risk_level": v.risk_level,
                "location": v.location, "description": v.description,
                "suggestion": v.suggestion,
            } for v in vulns],
            "counts": counts,
        })
    return send_file(path, mimetype="text/plain", as_attachment=True,
                     download_name=f"{audit_id}_审计报告.txt",
                     conditional=True, max_age=300)
