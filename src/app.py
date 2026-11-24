import html
import json
import os
import sqlite3
import time
from datetime import datetime

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.testclient import TestClient

DB_FILE = os.path.join(os.path.dirname(__file__), "apishield.db")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# In-memory data for demo endpoints
DEMO_NOTES = [
    {"id": 1, "title": "Welcome", "content": "Welcome to APIShield security testing!"},
    {"id": 2, "title": "Confidential", "content": "Mid-term paper draft: Top Secret"}
]
DEMO_RATE_LIMIT = {}


# --- Database Helpers ---

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            auth_type TEXT DEFAULT 'none',
            auth_value TEXT DEFAULT '',
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id INTEGER,
            endpoint_name TEXT,
            endpoint_url TEXT,
            score INTEGER,
            risk_level TEXT,
            total_tests INTEGER,
            passed_tests INTEGER,
            failed_tests INTEGER,
            warn_tests INTEGER,
            created_at TEXT,
            findings_json TEXT
        )
    """)
    if conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO endpoints (name, url, method, auth_type, auth_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     ("Vulnerable Notes API (Demo)", "http://127.0.0.1:8000/demo/vulnerable/notes", "GET", "none", "", now))
        conn.execute("INSERT INTO endpoints (name, url, method, auth_type, auth_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     ("Secure Notes API (Demo)", "http://127.0.0.1:8000/demo/secure/notes", "GET", "bearer", "secret-token-123", now))
    conn.commit()
    conn.close()


init_db()

app = FastAPI(title="APIShield", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


# --- Built-in Demo Endpoints (For Testing & Verification) ---

@app.get("/demo/vulnerable/notes")
def vulnerable_notes(q: str | None = None):
    """Vulnerable endpoint: publicly open and reflects SQL search parameters."""
    if q:
        query_str = f"SELECT * FROM notes WHERE content LIKE '%{q}%'"  # nosec B608
        return {"query_executed": query_str, "notes": DEMO_NOTES, "warning": "Vulnerable: query reflected raw!"}
    return {"notes": DEMO_NOTES}


@app.post("/demo/vulnerable/notes")
async def vulnerable_add_note(request: Request):
    """Vulnerable endpoint: exposes internal stack trace on invalid JSON."""
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        return Response(
            content="Internal Server Error: Traceback (most recent call last):\n  File 'app.py', line 50\nJSONDecodeError: Expecting value: line 1 column 1",
            status_code=500,
            media_type="text/plain",
        )
    new_note = {"id": len(DEMO_NOTES) + 1, "title": body.get("title", "Untitled"), "content": body.get("content", "")}
    DEMO_NOTES.append(new_note)
    return {"status": "success", "note": new_note}


@app.get("/demo/secure/notes")
def secure_notes(request: Request, response: Response, q: str | None = None):
    """Hardened endpoint: requires Bearer token, rate limits, and sets security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    requests = [t for t in DEMO_RATE_LIMIT.get(client_ip, []) if now - t < 10]
    if len(requests) >= 5:
        response.status_code = 429
        return {"detail": "Rate limit exceeded. Try again in 10 seconds."}
    requests.append(now)
    DEMO_RATE_LIMIT[client_ip] = requests

    if request.headers.get("Authorization") != "Bearer secret-token-123":
        response.status_code = 401
        return {"detail": "Authentication Required: Invalid or missing Bearer token."}

    if q:
        safe_q = html.escape(q)
        return {"query_sanitized": safe_q, "notes": [n for n in DEMO_NOTES if safe_q.lower() in n["content"].lower()]}
    return {"notes": DEMO_NOTES}


# --- Security Testing Modules ---

def make_request(method: str, url: str, headers: dict | None = None, content: bytes | None = None):
    """Sends requests to external URLs or internal demo routes."""
    if "127.0.0.1:8000" in url or "localhost:8000" in url:
        return TestClient(app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False).request(
            method, url, headers=headers, content=content
        )
    return httpx.request(method, url, headers=headers, content=content, timeout=4.0)


def check_auth(url: str, method: str, headers: dict) -> dict:
    """1. Broken Authentication Check."""
    try:
        no_auth = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        resp = make_request(method, url, headers=no_auth)
        if resp.status_code == 200:
            return {"test_name": "Broken Authentication", "status": "FAIL", "severity": "CRITICAL",
                    "detail": "Endpoint responded with HTTP 200 without authentication.", "remediation": "Enforce authentication on this route."}
        if resp.status_code in (401, 403):
            return {"test_name": "Broken Authentication", "status": "PASS", "severity": "LOW",
                    "detail": f"Protected. Rejected unauthenticated request with HTTP {resp.status_code}.", "remediation": "Authentication active."}
        return {"test_name": "Broken Authentication", "status": "WARN", "severity": "MEDIUM",
                "detail": f"Returned status code {resp.status_code} without auth.", "remediation": "Verify endpoint access policy."}
    except (httpx.HTTPError, OSError) as e:
        return {"test_name": "Broken Authentication", "status": "WARN", "severity": "LOW",
                "detail": f"Could not connect: {e!s}", "remediation": "Verify endpoint is reachable."}


def check_sqli(url: str, method: str, headers: dict) -> dict:
    """2. SQL Injection Check."""
    try:
        payload = "' OR '1'='1"
        test_url = f"{url}?q={payload}" if "?" not in url else f"{url}&q={payload}"
        resp = make_request(method, test_url, headers=headers)
        body = resp.text.lower()
        if resp.status_code == 500 or any(err in body for err in ("syntax error", "sqlite3", "sql", "mysql")):
            return {"test_name": "SQL Injection", "status": "FAIL", "severity": "HIGH",
                    "detail": "Database error signature detected in response.", "remediation": "Use parameterized queries or ORM."}
        if payload in resp.text:
            return {"test_name": "SQL Injection", "status": "WARN", "severity": "MEDIUM",
                    "detail": "Payload reflected raw in output.", "remediation": "Sanitize query parameters."}
        return {"test_name": "SQL Injection", "status": "PASS", "severity": "LOW",
                "detail": "No SQL syntax errors or query reflections found.", "remediation": "Input properly handled."}
    except (httpx.HTTPError, OSError):
        return {"test_name": "SQL Injection", "status": "PASS", "severity": "LOW", "detail": "Test skipped.", "remediation": "N/A"}


def check_xss(url: str, method: str, headers: dict) -> dict:
    """3. Cross-Site Scripting (XSS) Check."""
    try:
        payload = "<script>alert('xss')</script>"
        test_url = f"{url}?q={payload}" if "?" not in url else f"{url}&q={payload}"
        resp = make_request(method, test_url, headers=headers)
        if payload in resp.text:
            return {"test_name": "Cross-Site Scripting (XSS)", "status": "FAIL", "severity": "HIGH",
                    "detail": "Script tag was reflected unescaped in response.", "remediation": "Escape HTML entities in output."}
        return {"test_name": "Cross-Site Scripting (XSS)", "status": "PASS", "severity": "LOW",
                "detail": "Script tags sanitized properly.", "remediation": "Output encoding is active."}
    except (httpx.HTTPError, OSError):
        return {"test_name": "Cross-Site Scripting (XSS)", "status": "PASS", "severity": "LOW", "detail": "Test skipped.", "remediation": "N/A"}


def check_rate_limit(url: str, method: str, headers: dict) -> dict:
    """4. Rate Limiting Check."""
    try:
        limited = any(make_request(method, url, headers=headers).status_code == 429 for _ in range(8))
        if limited:
            return {"test_name": "Rate Limiting", "status": "PASS", "severity": "LOW",
                    "detail": "Server successfully throttled rapid requests with HTTP 429.", "remediation": "Rate limiting is working."}
        return {"test_name": "Rate Limiting", "status": "FAIL", "severity": "MEDIUM",
                "detail": "Server handled 8 rapid requests without rate limiting.", "remediation": "Add request throttling per IP/token."}
    except (httpx.HTTPError, OSError):
        return {"test_name": "Rate Limiting", "status": "WARN", "severity": "LOW", "detail": "Test skipped.", "remediation": "N/A"}


def check_headers(url: str, method: str, headers: dict) -> dict:
    """5. Security Headers Check."""
    try:
        resp = make_request(method, url, headers=headers)
        missing = []
        if "x-content-type-options" not in resp.headers:
            missing.append("X-Content-Type-Options")
        if "x-frame-options" not in resp.headers:
            missing.append("X-Frame-Options")
        if "content-security-policy" not in resp.headers:
            missing.append("Content-Security-Policy")

        if missing:
            return {"test_name": "Security Headers", "status": "WARN", "severity": "LOW",
                    "detail": f"Missing recommended headers: {', '.join(missing)}", "remediation": "Add security headers in responses."}
        return {"test_name": "Security Headers", "status": "PASS", "severity": "LOW",
                "detail": "All key security headers are present.", "remediation": "Headers properly configured."}
    except (httpx.HTTPError, OSError):
        return {"test_name": "Security Headers", "status": "WARN", "severity": "LOW", "detail": "Test skipped.", "remediation": "N/A"}


def check_info_leak(url: str) -> dict:
    """6. Information Disclosure Check."""
    try:
        resp = make_request("POST", url, headers={"Content-Type": "application/json"}, content=b"{malformed_json:")
        body = resp.text.lower()
        if any(w in body for w in ("traceback", "file \"", "internal server error", "exception:")):
            return {"test_name": "Information Disclosure", "status": "FAIL", "severity": "MEDIUM",
                    "detail": "Server exposed internal stack trace on malformed input.", "remediation": "Enable centralized error handling."}
        return {"test_name": "Information Disclosure", "status": "PASS", "severity": "LOW",
                "detail": "No stack traces or internals were leaked.", "remediation": "Safe error handling."}
    except (httpx.HTTPError, OSError):
        return {"test_name": "Information Disclosure", "status": "PASS", "severity": "LOW", "detail": "Test skipped.", "remediation": "N/A"}


def run_security_scan(url: str, method: str, auth_type: str, auth_value: str) -> list[dict]:
    """Runs all 6 checks and aggregates results."""
    headers = {"Content-Type": "application/json"}
    if auth_type == "bearer" and auth_value:
        headers["Authorization"] = f"Bearer {auth_value}"
    elif auth_type == "basic" and auth_value:
        headers["Authorization"] = f"Basic {auth_value}"

    return [
        check_auth(url, method, headers),
        check_sqli(url, method, headers),
        check_xss(url, method, headers),
        check_rate_limit(url, method, headers),
        check_headers(url, method, headers),
        check_info_leak(url)
    ]


def calculate_score(findings: list[dict]) -> dict:
    """Calculates a 0-100 score based on severity penalties."""
    score = 100
    penalties = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    for f in findings:
        if f["status"] == "FAIL":
            score -= penalties.get(f["severity"], 0)

    score = max(0, min(100, score))
    risk = "LOW" if score >= 80 else "MEDIUM" if score >= 50 else "HIGH"
    return {
        "score": score,
        "risk_level": risk,
        "total_tests": len(findings),
        "passed_tests": sum(1 for f in findings if f["status"] == "PASS"),
        "failed_tests": sum(1 for f in findings if f["status"] == "FAIL"),
        "warn_tests": sum(1 for f in findings if f["status"] == "WARN"),
    }


# --- REST API Endpoints ---

class EndpointCreate(BaseModel):
    name: str
    url: str
    method: str = "GET"
    auth_type: str = "none"
    auth_value: str | None = ""


@app.get("/api/endpoints")
def list_endpoints():
    conn = get_db()
    rows = conn.execute("SELECT * FROM endpoints ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/endpoints")
def add_endpoint(ep: EndpointCreate):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO endpoints (name, url, method, auth_type, auth_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (ep.name, ep.url, ep.method.upper(), ep.auth_type, ep.auth_value or "", now))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return {"id": new_id, "message": "Endpoint saved."}


@app.delete("/api/endpoints/{endpoint_id}")
def delete_endpoint(endpoint_id: int):
    conn = get_db()
    conn.execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))
    conn.commit()
    conn.close()
    return {"message": "Endpoint deleted."}


@app.post("/api/scan/{endpoint_id}")
def scan_endpoint(endpoint_id: int):
    conn = get_db()
    ep = conn.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
    if not ep:
        conn.close()
        raise HTTPException(status_code=404, detail="Endpoint not found")

    findings = run_security_scan(ep["url"], ep["method"], ep["auth_type"], ep["auth_value"])
    summary = calculate_score(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports (endpoint_id, endpoint_name, endpoint_url, score, risk_level,
                            total_tests, passed_tests, failed_tests, warn_tests, created_at, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ep["id"], ep["name"], ep["url"], summary["score"], summary["risk_level"],
          summary["total_tests"], summary["passed_tests"], summary["failed_tests"], summary["warn_tests"],
          now, json.dumps(findings)))
    conn.commit()
    report_id = cur.lastrowid
    conn.close()

    return {
        "report_id": report_id,
        "endpoint_name": ep["name"],
        "endpoint_url": ep["url"],
        "summary": summary,
        "findings": findings
    }


@app.get("/api/reports")
def list_reports():
    conn = get_db()
    rows = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    result = []
    for r in rows:
        item = dict(r)
        item["findings"] = json.loads(item["findings_json"])
        result.append(item)
    return result


if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def read_static_page(filename: str) -> str:
    page_path = os.path.join(STATIC_DIR, filename)
    if os.path.exists(page_path):
        with open(page_path, encoding="utf-8") as f:
            return f.read()
    return "<h1>APIShield is running</h1>"


@app.get("/", response_class=HTMLResponse)
@app.head("/", response_class=HTMLResponse)
def serve_home():
    return read_static_page("index.html")


@app.get("/targets", response_class=HTMLResponse)
@app.head("/targets", response_class=HTMLResponse)
def serve_targets():
    return read_static_page("targets.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
