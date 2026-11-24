# APIShield — Student Study Guide & Viva Explanation

---

## 1. Project High-Level Overview (30-Second Pitch)

> **What is APIShield?**
> APIShield is an automated API security evaluation tool built with FastAPI and SQLite. It takes any API endpoint URL, runs 6 automated OWASP security tests against it using HTTP payloads, calculates an objective security score (0–100) based on severity penalties, and presents the findings and fixes on a dark-mode web dashboard.

---

## 2. Where Do the API Endpoints Come From?

**They are NOT random.** An API endpoint must be coded on a server to exist and respond.

1. **Built-in Demo Endpoints (in `src/app.py`):**
   - `@app.get("/demo/vulnerable/notes")` (Line 77)
   - `@app.get("/demo/secure/notes")` (Line 106)
   - These exist inside `app.py` so you can demonstrate a live vulnerability scan without needing an external website.

2. **What if you type a random URL (like `http://127.0.0.1:8000/demo/vulnerable/hello`)?**
   - Because `/demo/vulnerable/hello` was never coded in `app.py`, FastAPI will return **`404 Not Found`**.

3. **Can you scan external or real APIs?**
   - **Yes.** If you enter a real URL (e.g. `https://api.github.com` or another local server running on port 5000) into the dashboard's "Add Target" form, APIShield will send the security tests to that URL.

---

## 3. How the 6 Security Tests Run on the Target API

When you click **"Scan"** in the dashboard, the backend function `run_security_scan()` sends real HTTP requests with test payloads to the target:

```
                       ┌─── 1. Check Auth ──────> (Sends request with NO headers)
                       ├─── 2. Check SQLi ──────> (Sends URL + "?q=' OR '1'='1")
                       ├─── 3. Check XSS ───────> (Sends URL + "?q=<script>alert('xss')</script>")
  Target URL ─────────┼─── 4. Check Rate Limit > (Sends 8 rapid requests back-to-back)
                       ├─── 5. Check Headers ───> (Inspects response header dictionary)
                       └─── 6. Check Info Leak ─> (Sends malformed JSON: b"{malformed_json:")
```

### Detailed Logic of Each Test

| # | Test Name | Payload / Action | Failure Logic | Severity & Penalty |
|---|---|---|---|:---:|
| 1 | **Broken Authentication** (`check_auth`) | Strips any `Authorization` header and requests the endpoint. | If server returns `200 OK`, sensitive data is publicly accessible without a password. | **CRITICAL** (-30 pts) |
| 2 | **SQL Injection** (`check_sqli`) | Appends `?q=' OR '1'='1` to the query string. | If response text contains SQL errors (`sqlite3`, `syntax error`) or crashes with `500`. | **HIGH** (-20 pts) |
| 3 | **Cross-Site Scripting** (`check_xss`) | Appends `?q=<script>alert('xss')</script>`. | If the unescaped script tag is echoed back in the response body. | **HIGH** (-20 pts) |
| 4 | **Rate Limiting** (`check_rate_limit`) | Fires 8 rapid requests in a loop. | If the server handles all 8 without returning `HTTP 429 Too Many Requests`. | **MEDIUM** (-10 pts) |
| 5 | **Security Headers** (`check_headers`) | Inspects standard response headers. | Missing `X-Content-Type-Options`, `X-Frame-Options`, or `Content-Security-Policy`. | **LOW** (-5 pts) |
| 6 | **Information Disclosure** (`check_info_leak`) | Sends broken JSON body `b"{malformed_json:"`. | If response contains stack traces, line numbers, or internal file paths. | **MEDIUM** (-10 pts) |

---

## 4. How the Security Score is Calculated

In `calculate_score()`:
- Base score starts at **100**.
- Points are deducted for each **FAIL**:
  - **Critical:** -30
  - **High:** -20
  - **Medium:** -10
  - **Low:** -5
- Final score is bounded between **0 and 100**.

### Risk Tiers
- **Score $\ge$ 80:** `LOW RISK • PASSING`
- **Score 50 – 79:** `MEDIUM RISK`
- **Score < 50:** `HIGH RISK • CRITICAL`

---

## 5. Code Structure Overview (`src/app.py`)

1. **Database Setup (`init_db`, `get_db`)**:
   - `endpoints` table: Saved targets to scan.
   - `reports` table: Scan history log and JSON results.
2. **Demo Target Routes**:
   - `/demo/vulnerable/notes`: Intentionally flawed endpoint for live demos.
   - `/demo/secure/notes`: Hardened endpoint requiring token and headers.
3. **Scanner Functions**:
   - `make_request()`: Central helper sending requests via `TestClient` (for local app) or `httpx` (for remote).
   - `check_auth()`, `check_sqli()`, `check_xss()`, `check_rate_limit()`, `check_headers()`, `check_info_leak()`.
4. **API Routes**:
   - `GET /api/endpoints`: Returns target inventory.
   - `POST /api/endpoints`: Adds a new target.
   - `POST /api/scan/{id}`: Runs the scan, logs report to database, returns findings.
   - `GET /api/reports`: Returns previous scan history.
   - `GET /`: Serves the HTML frontend dashboard.

---

## 6. Viva Q&A Cheat Sheet

**Q1: What is the main objective of this project?**
> "To provide an automated, lightweight security testing platform for developers to evaluate REST APIs against common OWASP vulnerabilities before deploying to production."

**Q2: Why are there demo endpoints in `app.py`?**
> "They provide reference implementations: one intentionally vulnerable target and one hardened target, allowing anyone to verify that the scanner detects vulnerabilities accurately without needing internet access."

**Q3: How would a developer fix an SQL Injection finding reported by APIShield?**
> "By using parameterized queries or an ORM (like SQLAlchemy) rather than directly concatenating user input strings into SQL statements."
