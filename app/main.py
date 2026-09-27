"""辐照校准包 COSE_Sign1 复核 API。"""

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

import audit_service
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


# ---------------------------------------------------------------- 审计

@app.post("/api/audits", status_code=201)
def create_audit(body: AuditIn):
    """发起约束一致性审计；任何输入缺陷返回 400 且不生成审计编号。"""
    try:
        result = audit_service.build_audit(db, body.review_ids)
    except audit_service.AuditRejected as exc:
        raise HTTPException(status_code=400, detail={"errors": exc.errors})
    return db.create_audit(result)


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    """按审计编号读回冻结结果。"""
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
