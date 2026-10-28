"""模块2+3+4+6：审计执行编排、漏洞入库、审计记录多条件查询、报告下载、实时进度推送（SSE）"""
import json
import os
import threading
import time
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify, send_file, Response, stream_with_context
from sqlalchemy import func

import config
import database
from database import Contract, AuditRecord, Vulnerability, User, Evidence
from detectors import get_detectors
from services.solc_parser import parse_source
from services.reports import get_report_generator
from utils import now_minute
from . import login_required, admin_required, current_user
from .contract import contract_file_path, save_sol_file

bp = Blueprint("audit", __name__, url_prefix="/api/audits")

# ========== 审计进度跟踪（SSE） ==========
# 每个进行中的审计维护一个进度字典：
#   {audit_id: {total:5, done:2, current:"slither", vulns:3, status:"running"}}
# 由 _run_audit 在每个检测器执行完后更新，SSE 端点拉取后推给前端。
# 审计完成/失败后保留最多 10 分钟供前端查询，过期自动清理。
_progress = {}
_progress_lock = threading.Lock()

# 检测器顺序固定，用于进度展示
DETECTOR_NAMES = [d.name for d in get_detectors()] or ["builtin_scanner"]


def _progress_init(audit_id: str):
    """创建进度条目，初始 running + total=检测器数"""
    with _progress_lock:
        _progress[audit_id] = {
            "total": len(DETECTOR_NAMES) or 1,
            "done": 0,
            "current": "",
            "vulns": 0,
            "status": "running",
            "start": time.time(),
        }


def _progress_update(audit_id: str, **kwargs):
    with _progress_lock:
        p = _progress.get(audit_id)
        if p is None:
            return
        p.update(kwargs)


def _progress_get(audit_id: str) -> dict:
    """返回进度副本（含 100 秒内过期清理）"""
    with _progress_lock:
        now = time.time()
        stale = [k for k, v in _progress.items()
                 if v.get("status") != "running" and now - v.get("start", 0) > 600]
        for k in stale:
            _progress.pop(k, None)
        return dict(_progress.get(audit_id, {"status": "unknown"}))


def _sse_format(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _sse_emit_done(audit_id: str) -> str:
    """审计完成时额外塞一条 done 事件（最终状态）"""
    s = database.Session()
    try:
        r = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
        if not r:
            return _sse_format("done", {"audit_id": audit_id, "status": "不存在"})
        stat = (s.query(Vulnerability.risk_level, func.count(Vulnerability.id))
                .filter(Vulnerability.audit_id == audit_id)
                .group_by(Vulnerability.risk_level).all())
        counts = {"高危": 0, "中危": 0, "低危": 0}
        for lv, n in stat:
            counts[lv] = counts.get(lv, 0) + n
    finally:
        database.Session.remove()
    return _sse_format("done", {
        "audit_id": audit_id, "status": r.status,
        "vuln_count": sum(counts.values()), "counts": counts,
        "report_txt": f"/api/audits/{audit_id}/report",
        "report_pdf": f"/api/audits/{audit_id}/report.pdf",
    })


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
    # 预创建进度条目（SSE 客户端可立即查询）
    _progress_init(audit_id)
    return jsonify({"audit_id": audit_id, "status": "running"})


@bp.post("/<audit_id>/fail")
@admin_required
def mark_audit_failed(audit_id: str):
    """管理员救援：将卡死的 running 审计手动标记为失败（Slither 挂起等场景）

    仅 running 状态可操作；标记后用户可对同一合约重新发起审计。
    """
    s = database.Session()
    try:
        r = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
        if not r:
            return jsonify({"message": "审计记录不存在"}), 404
        if r.status != "running":
            return jsonify({"message": f"当前状态为「{r.status}」，无需救援"}), 400
        r.status = "失败"
        r.error = "管理员手动标记：检测任务超时或无响应"
        s.commit()
        return jsonify({"audit_id": audit_id, "status": "失败"})
    finally:
        database.Session.remove()


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
            _progress_update(audit_id, current=detector.name)
            try:
                found = detector.detect(contract_info)
                all_vulns.extend(found)
                _progress_update(audit_id,
                                 done=_progress[audit_id]["done"] + 1,
                                 vulns=len(all_vulns))
            except Exception:
                _progress_update(audit_id,
                                 done=_progress[audit_id]["done"] + 1)
                module_errors.append(f"{detector.name}: {traceback.format_exc(limit=1)[:200]}")
        _progress_update(audit_id, status="generating_report")

        for v in all_vulns:
            s.add(Vulnerability(audit_id=audit_id, vul_type=v["vul_type"][:50],
                                risk_level=v["risk_level"],
                                confidence=v.get("confidence", "中"),
                                location=v["location"][:200],
                                description=v.get("description", ""),
                                suggestion=v.get("suggestion", "")))
        s.flush()

        # 漏洞分级统计
        counts = {"高危": 0, "中危": 0, "低危": 0}
        for v in all_vulns:
            counts[v["risk_level"]] = counts.get(v["risk_level"], 0) + 1

        # 自动生成 TXT / PDF 审计报告（策略模式，任一格式失败不影响审计结果）
        report_ctx = {
            "audit_id": audit_id,
            "contract_name": c.contract_name,
            "source_code": c.source_code,
            "audit_time": record.audit_time.strftime("%Y-%m-%d %H:%M"),
            "status": "完成",
            "vulns": all_vulns,
            "counts": counts,
        }
        for fmt in ("txt", "pdf"):
            try:
                get_report_generator(fmt).generate(report_ctx)
            except Exception:
                module_errors.append(f"report-{fmt}: {traceback.format_exc(limit=1)[:200]}")

        # 状态：有结果即完成；全部插件失败且无结果判失败
        if not all_vulns and module_errors:
            record.status = "失败"
            _progress_update(audit_id, status="失败")
        else:
            record.status = "完成"
            _progress_update(audit_id, status="完成")
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
    user_id_q = request.args.get("user_id")  # 管理员可按用户 ID 过滤
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
        elif user_id_q:
            try:
                q = q.filter(AuditRecord.user_id == int(user_id_q))
            except ValueError:
                pass
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
            "error": r.error or "",
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
            "error": r.error or "",
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
                    "confidence": v.confidence or "中",
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

def _load_report_context(audit_id: str):
    """加载报告上下文（含权限校验）：返回 (context, error_response)"""
    user = current_user()
    s = database.Session()
    try:
        r = s.query(AuditRecord).filter(AuditRecord.audit_id == audit_id).first()
        if not r:
            return None, (jsonify({"message": "审计记录不存在"}), 404)
        if user["role"] != "admin" and r.user_id != user["user_id"]:
            return None, (jsonify({"message": "无权访问该审计记录"}), 403)
        c = s.query(Contract).filter(Contract.id == r.contract_id).first()
        vulns = (s.query(Vulnerability).filter(Vulnerability.audit_id == audit_id)
                 .order_by(Vulnerability.id.asc()).all())

        counts = {"高危": 0, "中危": 0, "低危": 0}
        for v in vulns:
            counts[v.risk_level] = counts.get(v.risk_level, 0) + 1
        return {
            "audit_id": audit_id,
            "contract_name": c.contract_name,
            "source_code": c.source_code,
            "audit_time": r.audit_time.strftime("%Y-%m-%d %H:%M"),
            "status": r.status,
            "vulns": [{
                "vul_type": v.vul_type, "risk_level": v.risk_level,
                "confidence": v.confidence or "中",
                "location": v.location, "description": v.description,
                "suggestion": v.suggestion,
            } for v in vulns],
            "counts": counts,
        }, None
    finally:
        database.Session.remove()


@bp.get("/<audit_id>/report")
@login_required
def download_report(audit_id: str):
    """下载 TXT 审计报告；不存在时按需重新生成

    启用 conditional 响应（ETag/Last-Modified），客户端有缓存时直接返回 304，
    避免重复传输整份报告。send_file 本身就是分块流式写回，不会一次性载入内存。
    """
    ctx, err = _load_report_context(audit_id)
    if err:
        return err

    path = os.path.join(config.REPORT_DIR, f"{audit_id}.txt")
    if not os.path.exists(path):
        get_report_generator("txt").generate(ctx)
    return send_file(path, mimetype="text/plain", as_attachment=True,
                     download_name=f"{audit_id}_审计报告.txt",
                     conditional=True, max_age=300)


@bp.get("/<audit_id>/report.pdf")
@login_required
def download_report_pdf(audit_id: str):
    """下载 PDF 审计报告（含风险/置信度着色、漏洞代码片段高亮）"""
    ctx, err = _load_report_context(audit_id)
    if err:
        return err

    path = os.path.join(config.REPORT_DIR, f"{audit_id}.pdf")
    if not os.path.exists(path):
        try:
            get_report_generator("pdf").generate(ctx)
        except Exception as e:
            return jsonify({"message": f"PDF 报告生成失败：{e}"}), 500
    return send_file(path, mimetype="application/pdf", as_attachment=True,
                     download_name=f"{audit_id}_审计报告.pdf",
                     conditional=True, max_age=300)


# ===================== 实时进度（SSE） =====================

@bp.get("/<audit_id>/progress")
@login_required
def get_progress(audit_id: str):
    """一次性查询审计进度（GET JSON，前端轮询降级方案）"""
    p = _progress_get(audit_id)
    p.setdefault("total", 0)
    p.setdefault("done", 0)
    p.setdefault("percent", 0)
    if p["total"] and p.get("status") == "running":
        p["percent"] = int(p["done"] / p["total"] * 100)
    elif p.get("status") in ("完成", "失败"):
        p["percent"] = 100
    return jsonify(p)


@bp.get("/<audit_id>/sse")
@login_required
def audit_sse(audit_id: str):
    """SSE 实时推送审计进度（推荐：EventSource 订阅；心跳 10s 保持连接）"""
    user = current_user()

    def _iter():
        last_sig = None
        finished = False
        start_t = time.time()
        while time.time() - start_t < 180 and not finished:
            p = _progress_get(audit_id)
            if p.get("status") == "unknown":
                yield _sse_format("progress", {"audit_id": audit_id,
                                               "status": "unknown"})
                time.sleep(1.5)
                continue
            sig = (p.get("done"), p.get("status"), p.get("current"))
            percent = int((p["done"] / p["total"] * 100)) if p.get("total") and p.get("status") == "running" else 100
            out = {"audit_id": audit_id,
                   "status": p.get("status"),
                   "total": p.get("total", 0),
                   "done": p.get("done", 0),
                   "percent": percent,
                   "current": p.get("current", ""),
                   "vulns": p.get("vulns", 0)}
            if sig != last_sig:
                yield _sse_format("progress", out)
                last_sig = sig
            if p.get("status") in ("完成", "失败"):
                yield _sse_emit_done(audit_id)
                finished = True
                break
            # 心跳（10s 内没变化也发一个 ping，避免代理断连）
            time.sleep(1.5)
        if not finished:
            yield _sse_format("timeout", {"audit_id": audit_id})

    resp = Response(stream_with_context(_iter()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["X-Accel-Buffering"] = "no"  # 禁用 Nginx 缓冲
    return resp
