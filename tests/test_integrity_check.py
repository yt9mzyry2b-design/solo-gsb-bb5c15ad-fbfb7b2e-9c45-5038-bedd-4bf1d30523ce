"""成品完整性巡检测试：巡检结论、隔离标记、下载/票据拒绝、删除清理、迁移。"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path

from fastapi.testclient import TestClient

from app import db, settings, storage


def _completed_session(client: TestClient, data: bytes, name: str = "data.bin") -> str:
    """上传一份完整文件并完成，返回 session_id。"""
    resp = client.post(
        "/api/v1/sessions",
        json={
            "filename": name,
            "total_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    )
    assert resp.status_code == 201, resp.text
    sid = resp.json()["session_id"]
    if data:
        r = client.put(
            f"/api/v1/sessions/{sid}/chunks?start=0&end={len(data)}", content=data
        )
        assert r.status_code == 200, r.text
    done = client.post(f"/api/v1/sessions/{sid}/complete")
    assert done.status_code == 200, done.text
    return sid


def _issue(client: TestClient, sid: str, *, minutes: int = 60, max_downloads: int = 1):
    r = client.post(
        f"/api/v1/sessions/{sid}/tickets",
        json={"expires_in_minutes": minutes, "max_downloads": max_downloads},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _quarantine_row(session_id: str) -> sqlite3.Row | None:
    return db.get_conn().execute(
        "SELECT * FROM integrity_quarantine WHERE session_id = ?", (session_id,)
    ).fetchone()


def _remaining(ticket_id: str) -> int:
    return db.get_conn().execute(
        "SELECT remaining_downloads FROM download_tickets WHERE id = ?",
        (ticket_id,),
    ).fetchone()["remaining_downloads"]


def test_ok_check_returns_actual_size_and_digest(client: TestClient) -> None:
    data = b"integrity ok" * 500
    sid = _completed_session(client, data)
    before = client.get(f"/api/v1/sessions/{sid}").json()

    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["quarantined"] is False
    assert body["quarantined_at"] is None
    assert body["actual_size"] == len(data)
    assert body["actual_sha256"] == hashlib.sha256(data).hexdigest()
    assert body["expected_size"] == len(data)
    assert body["expected_sha256"] == hashlib.sha256(data).hexdigest()

    # 校验通过不改变会话：状态与活动时间戳原样，库中无隔离标记。
    after = client.get(f"/api/v1/sessions/{sid}").json()
    for field in ("status", "bytes_received", "last_access_at", "expires_at", "completed_at"):
        assert after[field] == before[field]
    assert _quarantine_row(sid) is None

    # 下载与票据签发不受影响。
    assert client.get(f"/api/v1/sessions/{sid}/download").status_code == 200
    assert r.status_code == 200
    _issue(client, sid)


def test_ok_check_empty_file(client: TestClient) -> None:
    sid = _completed_session(client, b"", name="empty.txt")
    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["actual_size"] == 0
    assert body["actual_sha256"] == hashlib.sha256(b"").hexdigest()
    assert _quarantine_row(sid) is None


def test_check_requires_completed_session(client: TestClient) -> None:
    # 未知会话 → 404。
    assert client.post("/api/v1/sessions/deadbeef/integrity-check").status_code == 404

    # 上传中会话 → 409，不产生隔离标记。
    resp = client.post(
        "/api/v1/sessions",
        json={"filename": "x", "total_size": 10, "sha256": "a" * 64},
    )
    sid = resp.json()["session_id"]
    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "integrity check requires a completed session"
    assert _quarantine_row(sid) is None


def test_missing_artifact_quarantines(client: TestClient) -> None:
    data = b"will be deleted"
    sid = _completed_session(client, data)
    storage.artifact_path(sid).unlink()

    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "missing"
    assert body["quarantined"] is True
    assert body["quarantined_at"] is not None
    assert body["actual_size"] is None
    assert body["actual_sha256"] is None
    assert body["expected_size"] == len(data)

    row = _quarantine_row(sid)
    assert row is not None
    assert row["reason"] == "missing"
    assert row["actual_size"] is None
    assert row["actual_sha256"] is None

    # 会话下载被拒并带具体原因。
    dl = client.get(f"/api/v1/sessions/{sid}/download")
    assert dl.status_code == 403
    detail = dl.json()["detail"]
    assert detail["error"] == "session quarantined by integrity check"
    assert detail["reason"] == "missing"


def test_length_mismatch_quarantines(client: TestClient) -> None:
    data = b"original bytes"
    sid = _completed_session(client, data)
    with storage.artifact_path(sid).open("ab") as fh:
        fh.write(b"trailing garbage")

    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "length_mismatch"
    assert body["quarantined"] is True
    assert body["actual_size"] == len(data) + len(b"trailing garbage")
    assert body["expected_size"] == len(data)
    # 长度不符时摘要按实际内容计算并回显。
    assert body["actual_sha256"] == hashlib.sha256(
        data + b"trailing garbage"
    ).hexdigest()

    row = _quarantine_row(sid)
    assert row is not None
    assert row["reason"] == "length_mismatch"
    assert row["actual_size"] == len(data) + len(b"trailing garbage")


def test_sha256_mismatch_quarantines(client: TestClient) -> None:
    data = b"x" * 4096
    sid = _completed_session(client, data)
    corrupted = b"y" + data[1:]
    storage.artifact_path(sid).write_bytes(corrupted)

    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "sha256_mismatch"
    assert body["quarantined"] is True
    assert body["actual_size"] == len(data)  # 长度正确，仅摘要不符
    assert body["actual_sha256"] == hashlib.sha256(corrupted).hexdigest()
    assert body["expected_sha256"] == hashlib.sha256(data).hexdigest()

    row = _quarantine_row(sid)
    assert row is not None
    assert row["reason"] == "sha256_mismatch"
    assert row["actual_sha256"] == hashlib.sha256(corrupted).hexdigest()


def test_quarantine_blocks_tickets_without_decrement(client: TestClient) -> None:
    data = b"ticketed artifact"
    sid = _completed_session(client, data)
    ticket = _issue(client, sid, max_downloads=3)
    url = f"/api/v1/tickets/{ticket['ticket']}/download"

    # 隔离前凭票下载正常计数。
    assert client.get(url).status_code == 200
    assert _remaining(ticket["ticket_id"]) == 2

    # 破坏成品（等长篡改，只改摘要）并巡检隔离。
    storage.artifact_path(sid).write_bytes(b"X" + data[1:])
    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.json()["status"] == "sha256_mismatch"

    # 凭票下载被拒且不扣减次数。
    dl = client.get(url)
    assert dl.status_code == 403
    assert dl.json()["detail"]["error"] == "session quarantined by integrity check"
    assert dl.json()["detail"]["reason"] == "sha256_mismatch"
    assert _remaining(ticket["ticket_id"]) == 2

    # 会话下载与票据签发同样被拒。
    assert client.get(f"/api/v1/sessions/{sid}/download").status_code == 403
    issue = client.post(
        f"/api/v1/sessions/{sid}/tickets",
        json={"expires_in_minutes": 60, "max_downloads": 1},
    )
    assert issue.status_code == 403
    assert issue.json()["detail"]["error"] == "session quarantined by integrity check"

    # 次数仍未变。
    assert _remaining(ticket["ticket_id"]) == 2


def test_repeated_check_is_idempotent(client: TestClient) -> None:
    sid = _completed_session(client, b"repeat me")
    storage.artifact_path(sid).unlink()

    for _ in range(2):
        r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
        assert r.status_code == 200
        assert r.json()["status"] == "missing"
        assert r.json()["quarantined"] is True
    # 同一会话只有一条隔离标记（upsert）。
    n = db.get_conn().execute(
        "SELECT COUNT(*) AS n FROM integrity_quarantine WHERE session_id = ?", (sid,)
    ).fetchone()["n"]
    assert n == 1


def test_ok_check_does_not_clear_existing_quarantine(client: TestClient) -> None:
    data = b"fix me out of band"
    sid = _completed_session(client, data)
    storage.artifact_path(sid).write_bytes(b"X" + data[1:])  # 等长篡改
    assert (
        client.post(f"/api/v1/sessions/{sid}/integrity-check").json()["status"]
        == "sha256_mismatch"
    )

    # 带外修复成品后复检通过，但隔离标记保持（只能随会话删除清除）。
    storage.artifact_path(sid).write_bytes(data)
    r = client.post(f"/api/v1/sessions/{sid}/integrity-check")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["quarantined"] is True
    assert body["quarantined_at"] is not None
    assert _quarantine_row(sid) is not None
    assert client.get(f"/api/v1/sessions/{sid}/download").status_code == 403


def test_deleting_session_clears_quarantine(client: TestClient) -> None:
    sid = _completed_session(client, b"delete clears mark")
    storage.artifact_path(sid).unlink()
    assert client.post(f"/api/v1/sessions/{sid}/integrity-check").json()["quarantined"]
    assert _quarantine_row(sid) is not None

    # 删除会话清除隔离标记。
    assert client.delete(f"/api/v1/sessions/{sid}").status_code == 204
    assert _quarantine_row(sid) is None

    # 已删除会话再巡检得到 404，且不会重新写入标记。
    assert client.post(f"/api/v1/sessions/{sid}/integrity-check").status_code == 404
    assert _quarantine_row(sid) is None


def test_concurrent_check_and_delete_serialize(client: TestClient) -> None:
    data = b"race between check and delete"
    sid = _completed_session(client, data)
    storage.artifact_path(sid).write_bytes(b"corrupted")

    barrier = threading.Barrier(2)
    outcomes: dict[str, int] = {}

    def run_check() -> None:
        barrier.wait()
        outcomes["check"] = client.post(
            f"/api/v1/sessions/{sid}/integrity-check"
        ).status_code

    def run_delete() -> None:
        barrier.wait()
        outcomes["delete"] = client.delete(f"/api/v1/sessions/{sid}").status_code

    threads = [threading.Thread(target=run_check), threading.Thread(target=run_delete)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 巡检与删除按同一会话锁串行：要么先隔离后删除（标记随删除级联清除），
    # 要么先删除后巡检（404，不写标记）。两种结局下都不残留隔离标记。
    assert outcomes["delete"] == 204
    assert outcomes["check"] in (200, 404)
    assert _quarantine_row(sid) is None
    gone = db.get_conn().execute(
        "SELECT COUNT(*) AS n FROM upload_sessions WHERE id = ?", (sid,)
    ).fetchone()["n"]
    assert gone == 0


def test_init_db_migrates_legacy_database_to_v6(monkeypatch, tmp_path: Path) -> None:
    """v1 老库可平滑升级到含 integrity_quarantine 的最新结构，老数据保留。"""
    db_file = tmp_path / "legacy.db"
    raw = sqlite3.connect(str(db_file))
    raw.execute(
        "CREATE TABLE upload_sessions ("
        "id TEXT PRIMARY KEY, filename TEXT NOT NULL, total_size INTEGER NOT NULL, "
        "sha256_expected TEXT NOT NULL, chunk_size INTEGER NOT NULL, status TEXT NOT NULL, "
        "bytes_received INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, "
        "last_access_at TEXT NOT NULL, completed_at TEXT)"
    )
    raw.execute(
        "INSERT INTO upload_sessions VALUES ("
        "'sid1','f.bin',10,'" + "a" * 64 + "',4,'completed',10,"
        "'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','2026-01-01T00:00:00Z',"
        "'2026-01-01T00:00:00Z')"
    )
    raw.commit()
    raw.close()

    monkeypatch.setattr(settings, "data_dir", tmp_path)
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{db_file}")
    db._local.conn = None  # 丢弃线程缓存连接，强制按新 DATABASE_URL 建连。
    try:
        db.init_db()
        conn = db.get_conn()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.LATEST_USER_VERSION
        # 老数据保留。
        assert (
            conn.execute(
                "SELECT filename FROM upload_sessions WHERE id = 'sid1'"
            ).fetchone()["filename"]
            == "f.bin"
        )
        # 新表可用：写入隔离标记，会话删除时级联清除；再次初始化幂等。
        conn.execute(
            "INSERT INTO integrity_quarantine "
            "(session_id, reason, actual_size, actual_sha256, created_at) "
            "VALUES ('sid1','missing',NULL,NULL,'2026-01-03T00:00:00Z')"
        )
        conn.execute("DELETE FROM upload_sessions WHERE id = 'sid1'")
        assert (
            conn.execute(
                "SELECT COUNT(*) AS n FROM integrity_quarantine WHERE session_id = 'sid1'"
            ).fetchone()["n"]
            == 0
        )
        db.init_db()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.LATEST_USER_VERSION
    finally:
        db._local.conn = None
