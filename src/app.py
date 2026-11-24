import html
import json
import logging
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

logger = logging.getLogger("apishield")

DB_FILE = os.path.join(os.path.dirname(__file__), "apishield.db")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

DEMO_NOTES = [
    {"id": 1, "title": "Welcome Note", "content": "Welcome to APIShield testing!"},
    {"id": 2, "title": "Confidential Project", "content": "Exam question paper draft: Top Secret"}
]
DEMO_RATE_LIMIT = {}


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
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
    cursor.execute("""
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

    cursor.execute("SELECT COUNT(*) FROM endpoints")
    if cursor.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO endpoints (name, url, method, auth_type, auth_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("Vulnerable Notes API (Demo)", "http://127.0.0.1:8000/demo/vulnerable/notes", "GET", "none", "", now)
        )
        cursor.execute(
            "INSERT INTO endpoints (name, url, method, auth_type, auth_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("Secure Notes API (Demo)", "http://127.0.0.1:8000/demo/secure/notes", "GET", "bearer", "secret-token-123", now)
        )
    conn.commit()
    conn.close()


init_db()

app = FastAPI(title="APIShield", docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/demo/vulnerable/notes")
def vulnerable_get_notes(q: str | None = None):
    if q:
        query_str = f"SELECT * FROM notes WHERE content LIKE '%{q}%'"  # nosec B608
        return {"query_executed": query_str, "notes": DEMO_NOTES, "warning": "Vulnerable: query reflected unescaped!"}
    return {"notes": DEMO_NOTES}


@app.post("/demo/vulnerable/notes")
async def vulnerable_add_note(request: Request):
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        return Response(
            content="Internal Server Error: Traceback (most recent call last):\n  File 'app.py', line 78, in vulnerable_add_note\nJSONDecodeError: Expecting value: line 1 column 1",
            status_code=500,
            media_type="text/plain",
        )
    content = body.get("content", "")
    new_note = {"id": len(DEMO_NOTES) + 1, "title": body.get("title", "Untitled"), "content": content}
    DEMO_NOTES.append(new_note)
    return {"status": "success", "echoed_raw": content, "note": new_note}


@app.get("/demo/secure/notes")
def secure_get_notes(request: Request, response: Response, q: str | None = None):
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

    auth_header = request.headers.get("Authorization", "")
    if auth_header != "Bearer secret-token-123":
        response.status_code = 401
        return {"detail": "Authentication Required: Invalid or missing Bearer token."}

    if q:
        safe_q = html.escape(q)
        return {
            "query_sanitized": safe_q,
            "parameterized_query": "SELECT * FROM notes WHERE content LIKE :safe_query",
            "notes": [n for n in DEMO_NOTES if safe_q.lower() in n["content"].lower()]
        }

    return {"notes": DEMO_NOTES}


def get_scanner_client(target_url: str):
    if "127.0.0.1:8000" in target_url or "localhost:8000" in target_url:
        return TestClient(app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False)
    return httpx.Client(timeout=4.0)


def run_all_security_tests(url: str, method: str, auth_type: str, auth_value: str) -> list[dict]:
    findings = []
    headers = {"Content-Type": "application/json"}
    if auth_type == "bearer" and auth_value:
        headers["Authorization"] = f"Bearer {auth_value}"
    elif auth_type == "basic" and auth_value:
        headers["Authorization"] = f"Basic {auth_value}"

    with get_scanner_client(url) as client:
        # Broken Authentication
        try:
            no_auth_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
            resp = client.request(method, url, headers=no_auth_headers)
            if resp.status_code == 200:
                findings.append({
                    "test_name": "Broken Authentication",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": "Endpoint responded with HTTP 200 without authentication. Sensitive data is publicly exposed.",
                    "remediation": "Enforce strict token or session verification on this endpoint (e.g., Bearer JWT or API Key)."
                })
            elif resp.status_code in [401, 403]:
                findings.append({
                    "test_name": "Broken Authentication",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": f"Protected properly. Unauthenticated request rejected with HTTP {resp.status_code}.",
                    "remediation": "No action needed. Authentication is active."
                })
            else:
                findings.append({
                    "test_name": "Broken Authentication",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "detail": f"Endpoint returned unexpected status code {resp.status_code} without authentication.",
                    "remediation": "Verify endpoint access control policies."
                })
        except (httpx.HTTPError, OSError) as e:
            findings.append({
                "test_name": "Broken Authentication",
                "status": "WARN",
                "severity": "LOW",
                "detail": f"Could not reach endpoint: {e!s}",
                "remediation": "Check if the target server is running."
            })

        # SQL Injection
        try:
            sqli_payload = "' OR '1'='1"
            test_url = f"{url}?q={sqli_payload}" if "?" not in url else f"{url}&q={sqli_payload}"
            resp = client.request(method, test_url, headers=headers)
            body_text = resp.text.lower()
            sql_errors = ["syntax error", "sqlite3", "sql", "mysql", "ora-", "unterminated quotation"]

            if resp.status_code == 500 or any(err in body_text for err in sql_errors):
                findings.append({
                    "test_name": "SQL Injection",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": "Potential SQL Injection detected! Response contains database error signatures.",
                    "remediation": "Use parameterized queries (Prepared Statements) or ORM. Never concatenate user input into queries."
                })
            elif sqli_payload in resp.text:
                findings.append({
                    "test_name": "SQL Injection",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "detail": "SQL payload was reflected raw in the response body. Query logic might be vulnerable.",
                    "remediation": "Sanitize and validate all query parameters against an allow-list."
                })
            else:
                findings.append({
                    "test_name": "SQL Injection",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": "No SQL syntax errors or query leakage detected for payload: ' OR '1'='1",
                    "remediation": "Keep using parameterized inputs."
                })
        except (httpx.HTTPError, OSError) as err:
            logger.debug("SQL injection probe notice: %s", err)

        # Cross-Site Scripting (XSS)
        try:
            xss_payload = "<script>alert('xss')</script>"
            test_url = f"{url}?q={xss_payload}" if "?" not in url else f"{url}&q={xss_payload}"
            resp = client.request(method, test_url, headers=headers)
            if xss_payload in resp.text:
                findings.append({
                    "test_name": "Cross-Site Scripting (XSS)",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": "Input was reflected unescaped in the response body. Attackers can execute arbitrary JavaScript.",
                    "remediation": "Encode all output with HTML entities (e.g. html.escape()) and implement a Content Security Policy."
                })
            else:
                findings.append({
                    "test_name": "Cross-Site Scripting (XSS)",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": "Script tags were properly sanitized or stripped.",
                    "remediation": "Maintain contextual output encoding."
                })
        except (httpx.HTTPError, OSError) as err:
            logger.debug("XSS probe notice: %s", err)

        # Rate Limiting
        try:
            hit_limit = any(client.request(method, url, headers=headers).status_code == 429 for _ in range(8))
            if hit_limit:
                findings.append({
                    "test_name": "Rate Limiting",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": "Rate limiting is active. Throttled rapid bursts with HTTP 429 Too Many Requests.",
                    "remediation": "Keep current rate limiting configuration."
                })
            else:
                findings.append({
                    "test_name": "Rate Limiting",
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "detail": "No rate limiting detected. Server processed 8 rapid requests without any throttling.",
                    "remediation": "Implement token bucket or sliding-window rate limiting per IP or API client."
                })
        except (httpx.HTTPError, OSError) as err:
            logger.debug("Rate limit probe notice: %s", err)

        # Security Headers
        try:
            resp = client.request(method, url, headers=headers)
            missing = []
            if "x-content-type-options" not in resp.headers:
                missing.append("X-Content-Type-Options: nosniff")
            if "x-frame-options" not in resp.headers:
                missing.append("X-Frame-Options: DENY")
            if "content-security-policy" not in resp.headers:
                missing.append("Content-Security-Policy")

            if missing:
                findings.append({
                    "test_name": "Security Headers",
                    "status": "WARN",
                    "severity": "LOW",
                    "detail": f"Missing recommended defense-in-depth headers: {', '.join(missing)}",
                    "remediation": "Add security middleware to send X-Content-Type-Options, X-Frame-Options, and CSP headers."
                })
            else:
                findings.append({
                    "test_name": "Security Headers",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": "All critical security headers are present in the server response.",
                    "remediation": "Headers configured according to OWASP guidelines."
                })
        except (httpx.HTTPError, OSError) as err:
            logger.debug("Security headers probe notice: %s", err)

        # Information Disclosure
        try:
            bad_headers = dict(headers)
            bad_headers["Content-Type"] = "application/json"
            resp = client.post(url, headers=bad_headers, content=b"{invalid_json:")
            body_text = resp.text.lower()
            leak_keywords = ["traceback", "file \"", "line ", "internal server error", "exception:"]
            if any(kw in body_text for kw in leak_keywords):
                findings.append({
                    "test_name": "Information Disclosure",
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "detail": "Server leaks internal stack traces or debug information when receiving malformed input.",
                    "remediation": "Enable generic error handling in production. Log stack traces privately and show generic JSON errors."
                })
            else:
                findings.append({
                    "test_name": "Information Disclosure",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": "No sensitive server internals or stack traces were exposed during error states.",
                    "remediation": "Continue using centralized exception handling."
                })
        except (httpx.HTTPError, OSError) as err:
            logger.debug("Information disclosure probe notice: %s", err)

    return findings


def calculate_security_score(findings: list[dict]) -> dict:
    score = 100
    penalties = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    fail_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        if f["status"] == "FAIL":
            sev = f["severity"]
            fail_counts[sev] = fail_counts.get(sev, 0) + 1
            score -= penalties.get(sev, 0)

    score = max(0, min(100, score))
    risk = "LOW" if score >= 80 else "MEDIUM" if score >= 50 else "HIGH"

    return {
        "score": score,
        "risk_level": risk,
        "total_tests": len(findings),
        "passed_tests": sum(1 for f in findings if f["status"] == "PASS"),
        "failed_tests": sum(1 for f in findings if f["status"] == "FAIL"),
        "warn_tests": sum(1 for f in findings if f["status"] == "WARN"),
        "fail_counts": fail_counts
    }


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
def create_endpoint(ep: EndpointCreate):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO endpoints (name, url, method, auth_type, auth_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (ep.name, ep.url, ep.method.upper(), ep.auth_type, ep.auth_value or "", now)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return {"id": new_id, "message": "Endpoint saved successfully!"}


@app.delete("/api/endpoints/{endpoint_id}")
def delete_endpoint(endpoint_id: int):
    conn = get_db()
    conn.execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))
    conn.commit()
    conn.close()
    return {"message": "Endpoint deleted"}


@app.post("/api/scan/{endpoint_id}")
def scan_endpoint(endpoint_id: int):
    conn = get_db()
    ep = conn.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone()
    if not ep:
        conn.close()
        raise HTTPException(status_code=404, detail="Endpoint not found")

    findings = run_all_security_tests(
        url=ep["url"],
        method=ep["method"],
        auth_type=ep["auth_type"],
        auth_value=ep["auth_value"]
    )
    summary = calculate_security_score(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO reports (
            endpoint_id, endpoint_name, endpoint_url, score, risk_level,
            total_tests, passed_tests, failed_tests, warn_tests, created_at, findings_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ep["id"], ep["name"], ep["url"], summary["score"], summary["risk_level"],
        summary["total_tests"], summary["passed_tests"], summary["failed_tests"], summary["warn_tests"],
        now, json.dumps(findings)
    ))
    conn.commit()
    report_id = cursor.lastrowid
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
    rows = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 15").fetchall()
    conn.close()
    result = []
    for r in rows:
        item = dict(r)
        item["findings"] = json.loads(item["findings_json"])
        result.append(item)
    return result


if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
@app.head("/", response_class=HTMLResponse)
def serve_home():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, encoding="utf-8") as f:
            return f.read()
    return "<h1>APIShield is running</h1>"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
