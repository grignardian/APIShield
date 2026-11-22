# System Architecture Document
## APIShield — API Security Testing Platform

**Version:** 1.0  
**Date:** November 2026  
**Course:** Secure Software Engineering (SSE) — Mini Project  
**Group:** Group 6 | Semester 3 | B.Tech CSE (Cybersecurity) | JIIT Noida

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Layers](#2-architecture-layers)
3. [Component Descriptions](#3-component-descriptions)
4. [Data Flow](#4-data-flow)
5. [Security Design Decisions](#5-security-design-decisions)
6. [Module Descriptions](#6-module-descriptions)

---

## 1. System Overview

APIShield follows a classic **three-layer architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│              React 18 + Vite (port 5173)                    │
│    Dashboard │ Endpoint Manager │ Results Viewer │ Reports  │
└────────────────────────┬────────────────────────────────────┘
                         │  HTTP/JSON  (REST API)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                        │
│         FastAPI + Uvicorn  (port 8000)                      │
│                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │
│  │  /endpoints  │ │   /tests     │ │    /reports      │   │
│  │   (router)   │ │   (router)   │ │    (router)      │   │
│  └──────────────┘ └──────┬───────┘ └──────────────────┘   │
│                           │                                  │
│                  ┌────────▼─────────┐                       │
│                  │ security_engine  │                       │
│                  │  (7 test checks) │                       │
│                  └────────┬─────────┘                       │
│                           │  httpx (outbound probes)        │
│                           ▼                                  │
│                  [ Target API Endpoint ]                     │
└────────────────────────┬────────────────────────────────────┘
                         │  SQLAlchemy ORM
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                       DATA LAYER                             │
│                  SQLite  (apishield.db)                     │
│                                                             │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────────┐    │
│  │  endpoints │  │ test_results│  │     reports      │    │
│  └────────────┘  └─────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Architecture Layers

### Layer Summary Table

| Layer | Technology | Responsibility |
|---|---|---|
| **Presentation** | React 18, Vite, CSS | User interface: forms, tables, dashboards, reports |
| **Application** | FastAPI, Uvicorn, Python 3.11 | REST API, business logic, security test orchestration |
| **Security Engine** | Python, httpx | Active security probing of target endpoints |
| **Data** | SQLAlchemy ORM, SQLite | Persistence of endpoints, findings, reports |

---

## 3. Component Descriptions

### 3.1 Frontend (React / Vite)

The frontend is a Single Page Application (SPA) built with React 18 and bundled by Vite.

**Key components:**
- **Endpoint Manager** — Form to add/delete API endpoints; table listing registered endpoints
- **Test Runner** — Button to trigger `/tests/run/{id}`; live display of findings with severity colour-coding
- **Results Viewer** — Historical findings table fetched from `/tests/{id}`
- **Report Panel** — Displays Security Score, pass/fail/warn breakdown, and report timestamp

All communication with the backend is via `fetch()` calls to the FastAPI REST API (JSON over HTTP).

### 3.2 FastAPI Backend

The backend exposes a RESTful JSON API under three routers:

| Router | Prefix | Purpose |
|---|---|---|
| `endpoints.py` | `/endpoints` | CRUD operations for registered API endpoints |
| `tests.py` | `/tests` | Trigger security tests; retrieve saved findings |
| `reports.py` | `/reports` | Generate and retrieve security reports |

**Main application (`main.py`):**
- Registers all three routers
- Adds CORS middleware (permissive in dev, should be restricted in prod)
- Creates all database tables on startup (`Base.metadata.create_all`)
- Serves interactive API documentation at `/docs` (Swagger UI)

### 3.3 Security Engine (`security_engine.py`)

The core of APIShield. Contains seven independent test functions and a single entry-point:

```python
run_security_tests(endpoint_config: dict) -> list[dict]
```

Each test function is independently callable, returns a standardised finding dict (or list of dicts for headers), and catches all exceptions to return WARN instead of crashing.

### 3.4 Database (SQLite via SQLAlchemy)

Three ORM models are defined in `models.py`:

| Model | Table | Key Fields |
|---|---|---|
| `Endpoint` | `endpoints` | id, name, url, method, headers, body, auth_type, auth_value, created_at |
| `TestResult` | `test_results` | id, endpoint_id, test_name, status, severity, detail, timestamp |
| `Report` | `reports` | id, endpoint_id, generated_at, summary (JSON) |

Foreign key: `TestResult.endpoint_id` → `Endpoint.id`; `Report.endpoint_id` → `Endpoint.id`.

---

## 4. Data Flow

### 4.1 Adding an Endpoint

```
User  →  Frontend form  →  POST /endpoints/  →  Pydantic validation
      →  Endpoint ORM object  →  SQLite insert  →  201 response with ID
```

### 4.2 Running Security Tests

```
User  →  Frontend "Run Tests"  →  POST /tests/run/{id}
      →  Fetch Endpoint from DB
      →  Build endpoint_config dict
      →  security_engine.run_security_tests(config)
            ├─ test_authentication()   → httpx.request (no auth headers)
            ├─ test_sql_injection()    → httpx.request (SQLi payload)
            ├─ test_xss()              → httpx.request (XSS payload)
            ├─ test_rate_limiting()    → 15× httpx.request
            ├─ test_https()            → URL string check (no request)
            ├─ test_error_disclosure() → httpx.request (malformed JSON)
            └─ test_security_headers() → httpx.request (normal)
      →  Save each finding to TestResult table
      →  Return flat list of findings as JSON
```

### 4.3 Generating a Report

```
User  →  POST /reports/generate/{id}
      →  Fetch all TestResult rows for endpoint
      →  Count PASS / FAIL / WARN by severity
      →  Compute Security Score = max(0, 100 − CRITICAL×30 − HIGH×20 − MEDIUM×10 − LOW×5)
      →  Save Report row (summary JSON)
      →  Return report JSON
```

---

## 5. Security Design Decisions

### 5.1 CORS

CORS is configured using FastAPI's `CORSMiddleware`. In development, all origins are allowed for ease of local testing. In a production deployment, `allow_origins` should be restricted to the known frontend URL to prevent cross-origin request forgery.

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ← restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 5.2 Input Validation (Pydantic v2)

All incoming request bodies are validated by Pydantic v2 schemas defined in each router file. Invalid or missing fields return HTTP 422 with a structured error response. This prevents malformed data from reaching the database layer.

### 5.3 Parameterised Queries (ORM)

All database interactions use the SQLAlchemy ORM. Queries are constructed using Python objects and SQLAlchemy's query builder, which generates parameterised SQL statements internally. This eliminates the risk of SQL Injection in the backend itself.

```python
# Safe — parameterised internally by SQLAlchemy
ep = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
```

### 5.4 Secure Error Handling

- FastAPI's default exception handlers are used throughout.
- No Python stack traces are exposed in HTTP responses.
- The security engine wraps every test in a `try/except` block; errors become WARN findings, not 500 responses.
- Structured error responses always use `{"detail": "..."}` format.

### 5.5 Secrets Management

- Database URL and secret key are stored in a `.env` file loaded via `python-dotenv`.
- `.env` is listed in `.gitignore`; only `.env.example` (with placeholder values) is committed.
- Hardcoded secrets are not present anywhere in the codebase.

### 5.6 Least Privilege (DB Sessions)

SQLAlchemy sessions are created per-request using FastAPI's dependency injection (`Depends(get_db)`). Each session is closed immediately after the request completes (via a `finally` block in the generator), ensuring no session leaks between requests.

---

## 6. Module Descriptions

### 6.1 `app/security_engine.py`

The core analysis module. Contains all security test logic and the entry-point function.

| Function | Description |
|---|---|
| `_build_headers(config)` | Parses stored headers JSON and merges auth header |
| `_build_body(config)` | Parses stored body JSON |
| `_request(method, url, ...)` | Thin wrapper around `httpx.request` |
| `test_authentication(config)` | Sends unauthenticated request; checks response code |
| `test_sql_injection(config)` | Injects SQL payload; checks for 500 / SQL error keywords |
| `test_xss(config)` | Sends XSS payload in query param; checks reflection |
| `test_rate_limiting(config)` | Sends 15 rapid requests; checks for 429 response |
| `test_https(config)` | Checks URL scheme (pure string check, no network call) |
| `test_error_disclosure(config)` | Sends malformed JSON; checks for stack trace keywords |
| `test_security_headers(config)` | Sends normal request; checks response headers |
| `run_security_tests(config)` | Orchestrates all tests, returns flat list of findings |

### 6.2 `app/routers/endpoints.py`

CRUD router for API endpoint management.

| Endpoint | Method | Description |
|---|---|---|
| `/endpoints/` | POST | Create new endpoint (validates via `EndpointCreate`) |
| `/endpoints/` | GET | List all endpoints |
| `/endpoints/{id}` | GET | Get one endpoint (404 if not found) |
| `/endpoints/{id}` | DELETE | Delete endpoint (204 no content) |

### 6.3 `app/routers/tests.py`

Triggers and retrieves security test results.

| Endpoint | Method | Description |
|---|---|---|
| `/tests/run/{id}` | POST | Run all security tests; save to DB; return findings |
| `/tests/{id}` | GET | Retrieve saved findings for an endpoint |

### 6.4 `app/routers/reports.py`

Generates and retrieves security reports.

| Endpoint | Method | Description |
|---|---|---|
| `/reports/generate/{id}` | POST | Generate report with Security Score |
| `/reports/{id}` | GET | Get saved report for an endpoint |
| `/reports/` | GET | List all reports |

### 6.5 `app/models.py`

SQLAlchemy ORM models. Defines the three database tables (`endpoints`, `test_results`, `reports`) and their columns, types, and relationships.

### 6.6 `app/database.py`

SQLAlchemy engine and session factory.

```python
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

The `check_same_thread=False` flag is required for SQLite when using it with FastAPI's threading model.

### 6.7 `app/main.py`

Application entry point. Configures the FastAPI instance, registers CORS middleware, includes all routers, and hooks `Base.metadata.create_all(bind=engine)` to the startup event so tables are created automatically on first run.
