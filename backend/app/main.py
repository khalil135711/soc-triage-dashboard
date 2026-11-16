import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .enrichment import RULES, enrich
from .schemas import AlertIn, LoginIn, NoteIn, Status, StatusUpdate
from .security import (create_token, current_user, login_limiter, require_admin,
                       verify_password)

app = FastAPI(
    title="SOC Alert Triage Dashboard",
    description="REST-API zum Einspielen, Anreichern und Bearbeiten von Security-Alerts.",
    version="1.0.0",
)


@app.on_event("startup")
def startup() -> None:
    db.init_db()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'"
        )
    return response


# ---------- Auth ----------
@app.post("/api/auth/login", tags=["auth"])
def login(data: LoginIn, request: Request):
    login_limiter.check(request.client.host if request.client else "unknown")
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
    if not row or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(401, "Benutzername oder Passwort falsch")
    return {"access_token": create_token(row["username"], row["role"]),
            "token_type": "bearer", "role": row["role"], "username": row["username"]}


# ---------- Alerts ----------
@app.get("/api/alerts", tags=["alerts"])
def list_alerts(
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    status: Status | None = None,
    q: str | None = Query(None, max_length=100, description="Suche in Signatur/IP"),
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sort: str = Query("timestamp", pattern="^(timestamp|score|severity|status)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    user: dict = Depends(current_user),
):
    where, params = [], []
    if severity:
        where.append("severity = ?"); params.append(severity)
    if status:
        where.append("status = ?"); params.append(status.value)
    if q:
        where.append("(signature LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ?)")
        params += [f"%{q}%"] * 3
    if date_from:
        where.append("timestamp >= ?"); params.append(date_from)
    if date_to:
        where.append("timestamp <= ?"); params.append(date_to)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    # sort/order sind per Regex validiert -> sicher für f-String
    with db.get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts {clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM alerts {clause} ORDER BY {sort} {order} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}


@app.post("/api/alerts", status_code=201, tags=["alerts"])
def create_alert(alert: AlertIn, user: dict = Depends(current_user)):
    info = enrich(alert.signature, alert.severity.value, alert.source_ip)
    with db.get_db() as conn:
        cur = conn.execute(
            """INSERT INTO alerts (timestamp, source_ip, dest_ip, signature, severity,
                                   score, mitre_id, mitre_name, raw)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (alert.timestamp, alert.source_ip, alert.dest_ip, alert.signature,
             alert.severity.value, info["score"], info["mitre_id"], info["mitre_name"], alert.raw),
        )
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.get("/api/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: int, user: dict = Depends(current_user)):
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Alert nicht gefunden")
        notes = conn.execute(
            "SELECT * FROM notes WHERE alert_id = ? ORDER BY id", (alert_id,)).fetchall()
    return {**dict(row), "notes": [dict(n) for n in notes]}


@app.patch("/api/alerts/{alert_id}", tags=["alerts"])
def update_status(alert_id: int, body: StatusUpdate, user: dict = Depends(current_user)):
    with db.get_db() as conn:
        cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?",
                           (body.status.value, alert_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Alert nicht gefunden")
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row)


@app.delete("/api/alerts/{alert_id}", status_code=204, tags=["alerts"])
def delete_alert(alert_id: int, user: dict = Depends(require_admin)):
    with db.get_db() as conn:
        cur = conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Alert nicht gefunden")


@app.post("/api/alerts/{alert_id}/notes", status_code=201, tags=["alerts"])
def add_note(alert_id: int, body: NoteIn, user: dict = Depends(current_user)):
    with db.get_db() as conn:
        if not conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone():
            raise HTTPException(404, "Alert nicht gefunden")
        cur = conn.execute("INSERT INTO notes (alert_id, author, text) VALUES (?,?,?)",
                           (alert_id, user["username"], body.text))
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


# ---------- Stats & Rules ----------
@app.get("/api/stats", tags=["stats"])
def stats(user: dict = Depends(current_user)):
    with db.get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_sev = conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall()
        by_status = conn.execute("SELECT status, COUNT(*) c FROM alerts GROUP BY status").fetchall()
        per_day = conn.execute(
            "SELECT substr(timestamp,1,10) d, COUNT(*) c FROM alerts GROUP BY d ORDER BY d DESC LIMIT 14"
        ).fetchall()
        top_ips = conn.execute(
            "SELECT source_ip ip, COUNT(*) c FROM alerts GROUP BY source_ip ORDER BY c DESC LIMIT 5"
        ).fetchall()
        top_mitre = conn.execute(
            """SELECT mitre_id, mitre_name, COUNT(*) c FROM alerts
               WHERE mitre_id IS NOT NULL GROUP BY mitre_id ORDER BY c DESC LIMIT 5"""
        ).fetchall()
    return {
        "total": total,
        "by_severity": {r["severity"]: r["c"] for r in by_sev},
        "by_status": {r["status"]: r["c"] for r in by_status},
        "per_day": [{"day": r["d"], "count": r["c"]} for r in reversed(per_day)],
        "top_source_ips": [{"ip": r["ip"], "count": r["c"]} for r in top_ips],
        "top_mitre": [{"id": r["mitre_id"], "name": r["mitre_name"], "count": r["c"]} for r in top_mitre],
    }


@app.get("/api/rules", tags=["stats"])
def rules(user: dict = Depends(current_user)):
    return [{"keyword": k, "mitre_id": t, "mitre_name": n, "base_score": s} for k, t, n, s in RULES]


@app.get("/api/health", tags=["stats"])
def health():
    return {"status": "ok"}


# ---------- Frontend ----------
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", Path(__file__).resolve().parents[2] / "frontend"))
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(FRONTEND_DIR / "index.html")
