# Software Requirements Specification (SRS)
## APIShield — API Security Testing Platform

**Version:** 1.0  
**Date:** November 2026  
**Course:** Secure Software Engineering (SSE) — Mini Project  
**Group:** Group 6 | Semester 3 | B.Tech CSE (Cybersecurity) | JIIT Noida  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [Security Requirements](#4-security-requirements)
5. [Use Cases](#5-use-cases)

---

## 1. Introduction

### 1.1 Purpose

This document defines the software requirements for **APIShield**, an API Security Testing Platform developed as part of the Secure Software Engineering (SSE) course. The purpose of this SRS is to describe the system's functional and non-functional requirements, security requirements, and high-level use cases to serve as a reference for development, testing, and evaluation.

### 1.2 Scope

APIShield is a web application that enables users to:
- Register REST API endpoints for security analysis
- Automatically execute a suite of security tests against registered endpoints
- View detailed findings with severity ratings
- Generate and export security assessment reports
- Understand vulnerabilities through included sample (vulnerable and secure) APIs

The system targets developers, security engineers, and students learning API security concepts.

### 1.3 Definitions and Acronyms

| Term | Definition |
|---|---|
| **API** | Application Programming Interface — a web service endpoint |
| **Endpoint** | A registered API URL with its method, auth config, and headers |
| **Finding** | A single security test result: test name, status, severity, detail |
| **PASS** | The endpoint passed the security check |
| **FAIL** | The endpoint failed the security check (vulnerability found) |
| **WARN** | The check could not be conclusive; manual review is recommended |
| **SSE** | Secure Software Engineering |
| **SDLC** | Software Development Lifecycle |
| **XSS** | Cross-Site Scripting |
| **SQLi** | SQL Injection |
| **CORS** | Cross-Origin Resource Sharing |
| **ORM** | Object-Relational Mapper |

### 1.4 References

- OWASP API Security Top 10 (2023)
- OWASP Testing Guide v4.2
- FastAPI Documentation — https://fastapi.tiangolo.com
- SQLAlchemy Documentation — https://docs.sqlalchemy.org

---

## 2. Functional Requirements

### FR-01 — Endpoint Registration

**Description:** The system shall allow users to register an API endpoint by providing:
- Endpoint name (string, required)
- URL (string, required)
- HTTP method (GET / POST / PUT / DELETE / PATCH)
- Authentication type (none / bearer / basic)
- Authentication value (token or base64 credentials)
- Custom headers (JSON object)
- Request body (JSON object)

**Acceptance Criteria:** A registered endpoint is persisted in the database and assigned a unique integer ID. Duplicate names are allowed.

---

### FR-02 — Endpoint Listing and Retrieval

**Description:** The system shall allow users to list all registered endpoints and retrieve a single endpoint by its ID.

**Acceptance Criteria:**
- `GET /endpoints/` returns a JSON array of all endpoints.
- `GET /endpoints/{id}` returns the full endpoint record or HTTP 404 if not found.

---

### FR-03 — Endpoint Deletion

**Description:** The system shall allow users to delete a registered endpoint. Deleting an endpoint shall also remove all associated test results and reports.

**Acceptance Criteria:** `DELETE /endpoints/{id}` returns HTTP 204; the endpoint and its data are no longer retrievable.

---

### FR-04 — Security Test Execution

**Description:** The system shall run a predefined suite of automated security tests against a specified endpoint. Tests shall be executed synchronously and results persisted in the database.

**Acceptance Criteria:** `POST /tests/run/{endpoint_id}` returns a JSON list of findings. Each finding contains: `test_name`, `status` (PASS/FAIL/WARN), `severity` (LOW/MEDIUM/HIGH/CRITICAL), and `detail`.

---

### FR-05 — Authentication Check

**Description:** The system shall send a request to the endpoint **without** any authentication credentials and analyse the HTTP response code.

**Acceptance Criteria:**
- If the response is HTTP 200: finding is FAIL / CRITICAL — "Endpoint returns 200 without authentication."
- If the response is HTTP 401 or 403: finding is PASS.
- Otherwise: finding is WARN.

---

### FR-06 — Injection and XSS Testing

**Description:** The system shall test for SQL Injection by appending `' OR 1=1--` to request parameters, and for Cross-Site Scripting (XSS) by sending `<script>alert(1)</script>` in a query parameter.

**Acceptance Criteria:**
- SQLi FAIL (HIGH) if server returns 500 or response body contains SQL error keywords.
- XSS FAIL (HIGH) if the raw XSS payload is reflected unescaped in the response body.

---

### FR-07 — Rate Limiting and Transport Security

**Description:** The system shall:
- Send 15 rapid requests and check whether a 429 (Too Many Requests) is returned (rate limiting test).
- Verify that the endpoint URL uses the HTTPS scheme (transport security test).

**Acceptance Criteria:**
- Rate limiting: FAIL (MEDIUM) if no 429 is received; PASS if 429 is received.
- HTTPS: FAIL (MEDIUM) if URL starts with `http://`; PASS if `https://`.

---

### FR-08 — Security Headers and Error Disclosure

**Description:** The system shall:
- Check the response headers for the presence of `X-Content-Type-Options`, `X-Frame-Options`, and `Content-Security-Policy`.
- Send a malformed (invalid JSON) request body and check the response for stack trace keywords (`traceback`, `exception`, `at line`).

**Acceptance Criteria:**
- Each missing security header generates a WARN (LOW) finding.
- Error disclosure: FAIL (MEDIUM) if stack trace keywords are found in response; PASS otherwise.

---

### FR-09 — Report Generation

**Description:** The system shall generate a security report for an endpoint based on its latest test results, including:
- Count of PASS / FAIL / WARN findings
- A Security Score (0–100): `100 − (CRITICAL×30 + HIGH×20 + MEDIUM×10 + LOW×5)`, clamped to 0
- Summary JSON saved to the database

**Acceptance Criteria:** `POST /reports/generate/{endpoint_id}` returns a JSON report with score and breakdown. The report is persisted and retrievable via `GET /reports/{endpoint_id}`.

---

### FR-10 — Sample APIs

**Description:** The system shall include two sample FastAPI applications for learning and demonstration:
- **vulnerable_api.py** — Intentionally insecure API exhibiting common vulnerabilities
- **secure_api.py** — Hardened reference implementation with proper auth, headers, and input validation

**Acceptance Criteria:** Both sample APIs start independently on configurable ports and can be targeted by APIShield's security tests.

---

## 3. Non-Functional Requirements

### 3.1 Performance

| ID | Requirement |
|---|---|
| NFR-P1 | Security test suite for a single endpoint shall complete within 60 seconds under normal network conditions. |
| NFR-P2 | The backend API shall respond to list/CRUD operations within 500 ms under normal load. |
| NFR-P3 | The system shall support concurrent requests without data corruption (using per-request DB sessions). |

### 3.2 Usability

| ID | Requirement |
|---|---|
| NFR-U1 | The frontend dashboard shall display test results with colour-coded severity indicators. |
| NFR-U2 | All API responses shall use consistent JSON structures with descriptive field names. |
| NFR-U3 | Validation errors shall return HTTP 422 with a human-readable `detail` array. |

### 3.3 Reliability

| ID | Requirement |
|---|---|
| NFR-R1 | Each individual security test shall catch all exceptions and return a WARN finding rather than crashing. |
| NFR-R2 | Database writes shall use transactions with automatic rollback on failure. |
| NFR-R3 | The system shall pass all automated pytest tests before any deployment. |

### 3.4 Maintainability

| ID | Requirement |
|---|---|
| NFR-M1 | The codebase shall follow PEP 8 conventions and include docstrings for all public functions. |
| NFR-M2 | Each security test shall be an independently testable function in `security_engine.py`. |
| NFR-M3 | Adding a new security test shall require changes only to `security_engine.py` and `run_security_tests()`. |

---

## 4. Security Requirements

### 4.1 Authentication and Authorisation

| ID | Requirement |
|---|---|
| SR-A1 | The backend shall validate all Pydantic schemas before processing any request; malformed input returns HTTP 422. |
| SR-A2 | Sensitive configuration (database URL, secret key) shall be stored in `.env` files, never hardcoded. |
| SR-A3 | The `.env` file shall be listed in `.gitignore` and never committed to version control. |

### 4.2 Input Validation

| ID | Requirement |
|---|---|
| SR-V1 | All database queries shall use SQLAlchemy ORM (parameterised queries) to prevent SQL Injection in the backend itself. |
| SR-V2 | JSON fields stored in the database (headers, body) shall be serialised/deserialised safely using `json.dumps` / `json.loads` with exception handling. |
| SR-V3 | URL inputs shall be stored as-is; the security engine validates them during test execution. |

### 4.3 Secure Error Handling

| ID | Requirement |
|---|---|
| SR-E1 | The backend shall never return Python stack traces or internal exception messages to API clients. |
| SR-E2 | FastAPI's default exception handlers shall be used; custom handlers shall return only structured `{detail: ...}` responses. |
| SR-E3 | Security engine tests that encounter request errors shall return WARN findings rather than propagating exceptions. |

### 4.4 Least Privilege

| ID | Requirement |
|---|---|
| SR-L1 | Database sessions shall be created per-request and closed immediately after use (FastAPI Depends pattern). |
| SR-L2 | The SQLite database file shall be accessible only to the backend process. |
| SR-L3 | CORS settings shall be restricted to known origins in production (allow-all is acceptable for development only). |

---

## 5. Use Cases

### UC-01 — Add an API Endpoint

**Actor:** Developer / Security Engineer  
**Precondition:** The APIShield backend is running.  
**Main Flow:**
1. User opens the frontend dashboard.
2. User fills in the endpoint form (name, URL, method, auth, headers, body).
3. User clicks "Add Endpoint".
4. Frontend sends `POST /endpoints/` to the backend.
5. Backend validates the payload (Pydantic), persists the record, and returns the created endpoint with its assigned ID.
6. Frontend displays the new endpoint in the endpoint list.

**Alternate Flow — Validation Failure:** Backend returns HTTP 422; frontend displays the validation error to the user.

---

### UC-02 — Run Security Tests

**Actor:** Developer / Security Engineer  
**Precondition:** At least one endpoint is registered.  
**Main Flow:**
1. User selects an endpoint from the dashboard.
2. User clicks "Run Security Tests".
3. Frontend sends `POST /tests/run/{endpoint_id}` to the backend.
4. Backend runs all 7 security checks (authentication, SQLi, XSS, rate limiting, HTTPS, error disclosure, security headers).
5. Each test result is saved to the `TestResult` table.
6. Backend returns the flat list of findings to the frontend.
7. Frontend displays colour-coded findings (FAIL = red, WARN = amber, PASS = green) with severity badges.

**Alternate Flow — Request Error:** Individual failing tests return WARN findings; the suite completes regardless.

---

### UC-03 — View Dashboard

**Actor:** Developer / Security Engineer  
**Precondition:** Endpoints and test results exist in the database.  
**Main Flow:**
1. User opens the frontend dashboard.
2. Frontend fetches `GET /endpoints/` and displays the endpoint list.
3. User selects an endpoint to view its latest test results.
4. Frontend fetches `GET /tests/{endpoint_id}` and renders the findings table.
5. User views the Security Score and finding breakdown.

---

### UC-04 — Generate a Security Report

**Actor:** Developer / Security Engineer  
**Precondition:** Security tests have been run for the selected endpoint.  
**Main Flow:**
1. User clicks "Generate Report" for a tested endpoint.
2. Frontend sends `POST /reports/generate/{endpoint_id}`.
3. Backend retrieves the latest test results, calculates the Security Score, and saves the report.
4. Backend returns the report JSON (score, counts by severity, timestamp).
5. Frontend displays the report summary and allows the user to review findings.

**Alternate Flow — No Test Results:** Backend returns an appropriate error; frontend prompts the user to run tests first.
