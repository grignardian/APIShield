# APIShield

**Automated API Security Testing & Vulnerability Assessment Platform**

APIShield is a lightweight, automated security scanner that analyzes REST APIs for common vulnerabilities, misconfigurations, and attack vectors defined in the OWASP API Security Top 10. It evaluates endpoints against real-world security checks, calculates an overall security risk score (0–100), and provides actionable developer guidance.

---

## Features

- **Automated Vulnerability Probing:** Scans endpoints for Broken Authentication, SQL Injection, Cross-Site Scripting (XSS), Rate Limiting deficiencies, Missing Security Headers, and Information Leakage.
- **Weighted Security Scoring:** Calculates an objective 0–100 score and risk rating (`LOW`, `MEDIUM`, `HIGH`) based on finding severity.
- **Interactive Dark Dashboard:** Modern, stats-driven web UI featuring real-time metrics, test distribution meters, and target inventory management.
- **Side-by-Side Reference Targets:** Includes built-in vulnerable and hardened endpoints for immediate demonstration and testing.
- **Zero-Configuration Storage:** Uses an embedded SQLite database to persist configured endpoints, audit logs, and scan history.
- **Automated Test Suite:** Built-in unit and integration tests powered by Pytest.

---

## Repository Structure

```
├── documentation/          # Software Requirements (SRS), UML diagrams, and architecture docs
│   ├── SRS.md
│   ├── UML_DIAGRAMS.md
│   ├── architecture.md
│   └── project_synopsis.pdf
├── src/                    # Application source code
│   ├── app.py              # FastAPI server, security test engine, and SQLite database
│   └── static/             # Frontend assets
│       ├── index.html      # React single-page dashboard
│       └── js/             # Local offline React libraries
├── tests/                  # Automated test suite
│   └── test_apishield.py   # Pytest unit & integration tests
├── .gitignore              # Standard git exclusion rules
├── README.md               # Project documentation
└── requirements.txt        # Python package dependencies
```

---

## Quick Start

### 1. Prerequisites
- Python 3.10 or higher
- Git

### 2. Clone and Install Dependencies
```bash
git clone <repository-url>
cd SsePBL
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python src/app.py
```

The application will start on **port 8000**:
- **Web Dashboard:** [http://localhost:8000](http://localhost:8000)

---

## Automated Security Checks

APIShield executes six automated security checks against any configured API endpoint:

| Security Check | OWASP API Category | Severity | Detection Logic |
|---|---|:---:|---|
| **Broken Authentication** | OWASP API 1 | **CRITICAL** | Submits requests without credentials. Exposing data or returning HTTP 200 without authentication flags a critical failure. |
| **SQL Injection (SQLi)** | OWASP API 8 | **HIGH** | Injects common SQL test payloads (`' OR '1'='1`) and checks for unhandled database errors or reflection. |
| **Cross-Site Scripting (XSS)** | OWASP API 8 | **HIGH** | Injects script tags (`<script>alert('xss')</script>`) to evaluate whether input is sanitized or echoed unescaped. |
| **Rate Limiting & Abuse** | OWASP API 4 | **MEDIUM** | Sends rapid bursts of requests to verify whether the server enforces throttling (HTTP 429 Too Many Requests). |
| **Information Disclosure** | OWASP API 7 | **MEDIUM** | Sends malformed payloads to verify that the server does not leak internal stack traces or debug information. |
| **Defense-in-Depth Headers** | Security Baseline | **LOW** | Checks for protective browser response headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`). |

---

## Security Scoring Model

The security score is calculated using weighted deductions from an initial baseline of 100:

$$\text{Security Score} = \max\left(0, 100 - (\text{CRITICAL}\times 30 + \text{HIGH}\times 20 + \text{MEDIUM}\times 10 + \text{LOW}\times 5)\right)$$

### Risk Rating Scale
- **80 – 100 (LOW RISK):** The endpoint meets essential security baselines.
- **50 – 79 (MEDIUM RISK):** Moderate vulnerabilities or missing hardening measures detected.
- **0 – 49 (HIGH / CRITICAL RISK):** Critical flaws detected (e.g., exposed authentication, SQL injection vulnerability). Immediate remediation recommended.

---

## Verification & Testing

### Run Pytest Test Suite
Execute the full automated test suite covering CRUD operations, scanner accuracy, and demo endpoints:
```bash
pytest tests/ -v
```

### Code Quality & Static Security Analysis
Linting and static code security checks can be executed using Ruff and Bandit:
```bash
# Code style and syntax check
ruff check src/

# Static Application Security Testing (SAST)
bandit -r src/ --skip B104
```

---

## Demo Endpoints

APIShield includes built-in endpoints for instant testing:
- **Vulnerable Target:** `http://localhost:8000/demo/vulnerable/notes` (permits unauthenticated access, reflects raw input, lacks security headers; typical score ~40)
- **Hardened Target:** `http://localhost:8000/demo/secure/notes` (requires Bearer token `secret-token-123`, enforces rate limiting, returns protective security headers; typical score 100)
