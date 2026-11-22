# APIShield — Automated API Security Testing Platform

**Course:** Secure Software Engineering (`26B11CS219`)  
**Department:** Computer Science and Engineering (Cybersecurity), JIIT Noida  
**Group 6 — Semester 3**  

| S. No. | Name | Roll Number |
|---|---|---|
| 1 | Shambhavi Singh | 992501230049 |
| 2 | Labhansh Vashisht | 992501230050 |
| 3 | Mohd. Nauman Ali | 992501230060 |
| 4 | Kartik Virmani | 992501230039 |

---

## Repository Structure

```
├── documentation/          # Software Requirements (SRS), UML diagrams, and Synopsis
│   ├── SRS.md
│   ├── UML_DIAGRAMS.md
│   ├── architecture.md
│   └── SSEMiniProjectSynopsis_Group6.pdf
├── src/                    # FastAPI backend, SQLite database, and React frontend
│   ├── app.py
│   └── static/
│       ├── index.html
│       └── js/
├── tests/                  # Automated pytest security test suite
│   └── test_apishield.py
├── .gitignore              # Git ignore rules
├── README.md               # Project documentation
└── requirements.txt        # Minimal Python dependencies
```

All services run on **port 8000**:
- Web Dashboard: `http://localhost:8000`
- Swagger API Documentation: `http://localhost:8000/docs`
- Vulnerable Demo Target: `http://localhost:8000/demo/vulnerable/notes`
- Hardened Secure Target: `http://localhost:8000/demo/secure/notes`

---

## Instructions to Run

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Server
```bash
python src/app.py
```

### 3. Access the Dashboard
Open your browser at:
**http://localhost:8000**

---

## Automated Security Checks Implemented

| Check Name | Target Threat | Severity | Implementation Logic |
|---|---|:---:|---|
| **Broken Authentication** | OWASP API 1 | **CRITICAL** | Evaluates response when credentials are omitted. Exposing data returns status FAIL. |
| **SQL Injection** | OWASP API 8 | **HIGH** | Injects `' OR '1'='1` in query strings; checks for database syntax errors or data exposure. |
| **Cross-Site Scripting (XSS)** | OWASP API 8 | **HIGH** | Injects script payloads; evaluates whether the server echoes raw, unescaped tags. |
| **Rate Limiting / Abuse** | OWASP API 4 | **MEDIUM** | Emits rapid request bursts; validates whether the endpoint throttles with HTTP 429. |
| **Information Disclosure** | OWASP API 7 | **MEDIUM** | Sends malformed bodies; evaluates whether internal stack traces or debug info leak. |
| **Defense-in-Depth Headers** | Security Baseline | **LOW** | Checks for Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options. |

---

## Security Scoring Model

$$\text{Security Score} = \max\left(0, 100 - (\text{CRITICAL}\times 30 + \text{HIGH}\times 20 + \text{MEDIUM}\times 10 + \text{LOW}\times 5)\right)$$

- **Score >= 80**: **LOW RISK** (Green) — System meets security baseline
- **Score 50 - 79**: **MEDIUM RISK** (Amber) — Vulnerabilities require remediation
- **Score < 50**: **HIGH RISK** (Red) — Critical flaws detected

---

## Automated Verification Tests

Execute the automated test suite with:
```bash
pytest tests/ -v
```

---

## Code Quality & Security Analysis (Ruff & Bandit)

As specified in the project synopsis, code quality linting and static security analysis are performed using **Ruff** and **Bandit**:

```bash
# 1. Code Quality & Formatting Check (Ruff)
ruff check src/

# 2. Static Application Security Testing (Bandit)
bandit -r src/ --skip B104
```

> **Bandit SAST Insight:** Bandit actively detects the intentional string-concatenation SQL vulnerability in our demo vulnerable endpoint (`CWE-89: B608`), validating the vulnerability detection mechanism.

---

## Academic Viva / Presentation Reference

**Q1: How does APIShield apply Secure SDLC concepts?**  
> "During the testing phase of the SDLC, standard functional testing verifies only intended business logic. APIShield introduces automated security testing to verify access control, input handling, and resilience against common OWASP API threats."

**Q2: What separates the Vulnerable and Secure sample APIs?**  
> "The vulnerable endpoint allows unauthenticated access, lacks rate limiting, and omits HTTP security headers. The secure endpoint enforces Bearer token authentication, throttles rapid traffic bursts (HTTP 429), and sets browser defense-in-depth security headers."

**Q3: How are reports persisted?**  
> "Audit records are stored in a local SQLite database (`apishield.db`), recording timestamps, scores, risk ratings, and actionable developer remediation advice."
# APIShield
