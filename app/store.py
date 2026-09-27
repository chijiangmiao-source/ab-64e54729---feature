"""复核记录持久化（SQLite）。拒绝记录同样落库，可按编号重新读取。"""

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone


class Store:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reviews (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    public_key_hex TEXT NOT NULL,
                    package_hex TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def create(self, public_key_hex: str, package_hex: str, result: dict) -> dict:
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            for _ in range(5):
                rid = uuid.uuid4().hex[:12]
                try:
                    self._conn.execute(
                        "INSERT INTO reviews (id, created_at, public_key_hex, package_hex, result_json)"
                        " VALUES (?, ?, ?, ?, ?)",
                        (rid, created, public_key_hex, package_hex,
                         json.dumps(result, ensure_ascii=False)),
                    )
                    self._conn.commit()
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise RuntimeError("无法分配复核编号")
        return {"id": rid, "created_at": created, **result}

    def get(self, review_id: str):
        cur = self._conn.execute(
            "SELECT id, created_at, result_json FROM reviews WHERE id = ?", (review_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {"id": row[0], "created_at": row[1], **json.loads(row[2])}

    def list_recent(self, limit: int = 50):
        cur = self._conn.execute(
            "SELECT id, created_at, result_json FROM reviews ORDER BY rowid DESC LIMIT ?",
            (limit,),
        )
        out = []
        for rid, created, rj in cur.fetchall():
            r = json.loads(rj)
            out.append({
                "id": rid,
                "created_at": created,
                "verdict": r.get("verdict"),
                "payload_sha256": r.get("payload_sha256"),
            })
        return out
