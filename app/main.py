"""辐照校准包 COSE_Sign1 复核 API。"""

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

import audit as audit_mod
import cose
import store as store_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="辐照校准包 COSE 复核", version="1.1.0")
db = store_mod.Store(os.environ.get("DB_PATH", os.path.join(BASE_DIR, "reviews.db")))


class ReviewIn(BaseModel):
    public_key_hex: str
    package_hex: str


class AuditIn(BaseModel):
    review_ids: list[str]


@app.post("/api/reviews", status_code=201)
def create_review(body: ReviewIn):
    """提交复核：无论通过与否都持久化记录，返回复核编号与逐项原因。"""
    result = cose.verify_review(body.public_key_hex, body.package_hex)
    return db.create(body.public_key_hex, body.package_hex, result)


@app.get("/api/reviews/{review_id}")
def get_review(review_id: str):
    """按复核编号重新读取记录。"""
    rec = db.get(review_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="复核记录不存在")
    return rec


@app.get("/api/reviews")
def list_reviews():
    """最近复核记录摘要（含可观察的拒绝记录）。"""
    return db.list_recent()


@app.post("/api/audits", status_code=201)
def create_audit(body: AuditIn):
    """对若干已通过复核记录发起约束一致性审计。

    引用校验（缺字段、探测器不一致、重复引用、非法有理数、编号不存在或
    非通过记录）一律 400 拒绝，不生成审计编号；成功后冻结结果落库。
    """
    review_ids = body.review_ids
    if not isinstance(review_ids, list) or not review_ids:
        raise HTTPException(status_code=400, detail="review_ids 必须是非空数组")
    normalized = []
    for rid in review_ids:
        if not isinstance(rid, str) or not rid.strip():
            raise HTTPException(status_code=400, detail="复核编号必须是非空字符串")
        normalized.append(rid.strip())
    if len(set(normalized)) != len(normalized):
        raise HTTPException(status_code=400, detail="引用的复核编号存在重复")

    rows = db.get_review_rows(normalized)
    missing = [rid for rid in normalized if not any(r["id"] == rid for r in rows)]
    if missing:
        raise HTTPException(
            status_code=400,
            detail="以下编号无已保存的复核记录：" + "、".join(missing),
        )
    try:
        detector_id, constraints = audit_mod.collect_constraints(
            rows, cose.verify_review
        )
        result = audit_mod.run_audit(detector_id, constraints)
    except audit_mod.AuditReject as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["source_review_ids"] = normalized
    return db.create_audit(result)


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    """按审计编号读回冻结的审计结果。"""
    rec = db.get_audit(audit_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    return rec


@app.get("/api/audits")
def list_audits():
    """最近审计记录摘要。"""
    return db.list_recent_audits()


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))
