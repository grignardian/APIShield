# APIShield — UML & System Design Diagrams

**Course:** Secure Software Engineering (26B11CS219)  
**Group:** Group 6 — Semester 3, B.Tech CSE (Cybersecurity), JIIT Noida  
**Tools:** Draw.io / UML 2.5 Standards  

---

## 1. Use Case Diagram (UML)

```
                    ┌────────────────────────────────────────────────────────┐
                    │                      APIShield                         │
                    │                                                        │
                    │       ( Register / Configure API Endpoint )            │
                    │                    ^          ^                        │
                    │                   /            \                       │
                    │           <<include>>        <<include>>               │
                    │                 /                \                     │
   ┌──────────┐     │     ( Run Automated Security Scan )                    │
   │          ├─────┼────────────────> │                                     │
   │ Security │     │                  ├─>> [ Broken Auth Check ]            │
   │ Analyst  │     │                  ├─>> [ SQLi Check ]                   │
   │  / User  │     │                  ├─>> [ XSS Reflection Check ]         │
   │          │     │                  ├─>> [ Rate Limiting Check ]          │
   │          │     │                  ├─>> [ Security Headers Check ]       │
   │          │     │                  └─>> [ Error Disclosure Check ]       │
   │          │     │                                                        │
   │          ├─────┼─────> ( View Risk Dashboard & Findings )               │
   │          │     │                                                        │
   │          ├─────┼─────> ( Generate Structured Assessment Report )        │
   │          │     │                                                        │
   │          ├─────┼─────> ( Test Vulnerable vs Secure Demo Targets )       │
   └──────────┘     │                                                        │
                    └────────────────────────────────────────────────────────┘
```

---

## 2. System Architecture / Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PRESENTATION LAYER                            │
│           Single-Page React 18 Application (Inter Font / UI)            │
│  [ Dashboard View ]   [ Endpoints Manager ]   [ Scanner & Reports Tab ] │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP / JSON REST APIs
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       APPLICATION & BACKEND LAYER                       │
│                     Python 3.14 + FastAPI + OpenAPI                     │
│                                                                         │
│  ┌───────────────────────┐             ┌─────────────────────────────┐  │
│  │ API Endpoint Manager  │             │   Vulnerability Assessor    │  │
│  │ (CRUD on /endpoints)  │             │   (Score Formula: 0-100)    │  │
│  └──────────┬────────────┘             └──────────────┬──────────────┘  │
│             │                                         │                 │
│  ┌──────────▼─────────────────────────────────────────▼──────────────┐  │
│  │                Automated Security Test Engine                     │  │
│  │                                                                   │  │
│  │  • Auth Validator       • SQLi Prober       • XSS Reflector       │  │
│  │  • Rate Limiter Prober  • Header Inspector  • Error Analyzer      │  │
│  └──────────────────────────────────┬────────────────────────────────┘  │
│                                     │                                   │
│  ┌──────────────────────────────────▼────────────────────────────────┐  │
│  │             Controlled Sample APIs (Benchmarking)                 │  │
│  │    /demo/vulnerable (OWASP Flaws)  │  /demo/secure (Mitigated)    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                             DATA LAYER                                  │
│                 SQLite Relational Database (apishield.db)               │
│                                                                         │
│   ┌────────────────────┐                   ┌────────────────────────┐   │
│   │  endpoints table   │ 1               * │     reports table      │   │
│   │  - id (PK)         ├───────────────────┤  - id (PK)             │   │
│   │  - name            │                   │  - endpoint_id (FK)    │   │
│   │  - url             │                   │  - score, risk_level   │   │
│   │  - method          │                   │  - findings_json       │   │
│   │  - auth_type/val   │                   │  - created_at          │   │
│   └────────────────────┘                   └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Sequence Diagram — Automated Security Scan Flow

```
User/Browser             APIShield Backend          Target API             SQLite DB
     │                           │                       │                     │
     │ 1. POST /api/scan/{id}    │                       │                     │
     ├──────────────────────────>│                       │                     │
     │                           │ 2. Fetch endpoint cfg │                     │
     │                           ├────────────────────────────────────────────>│
     │                           │<────────────────────────────────────────────┤
     │                           │    (URL, method, auth)│                     │
     │                           │                       │                     │
     │                           │ 3. Check Auth (No-token)                    │
     │                           ├──────────────────────>│                     │
     │                           │<──────────────────────┤ (Status 200/401)    │
     │                           │                       │                     │
     │                           │ 4. Check SQLi / XSS   │                     │
     │                           ├──────────────────────>│                     │
     │                           │<──────────────────────┤ (Payload response)  │
     │                           │                       │                     │
     │                           │ 5. Rapid burst (x8)   │                     │
     │                           ├──────────────────────>│                     │
     │                           │<──────────────────────┤ (Status 429/200)    │
     │                           │                       │                     │
     │                           │ 6. Check Headers & Err│                     │
     │                           ├──────────────────────>│                     │
     │                           │<──────────────────────┤                     │
     │                           │                       │                     │
     │                           │ 7. Calculate score & risk level             │
     │                           │    Score = 100 - penalties                 │
     │                           │                                             │
     │                           │ 8. Save report & findings                   │
     │                           ├────────────────────────────────────────────>│
     │                           │<────────────────────────────────────────────┤
     │                           │                                             │
     │ 9. Return JSON Report     │                                             │
     │<──────────────────────────┤                                             │
     │ (Score, Findings, Remedy) │                                             │
     ▼                           ▼                                             ▼
```

---

## 4. Class / Data Model Diagram (UML)

```
┌─────────────────────────────────┐           ┌────────────────────────────────────────┐
│           Endpoint              │           │                Report                  │
├─────────────────────────────────┤           ├────────────────────────────────────────┤
│ + id: int (PK)                  │ 1       * │ + id: int (PK)                         │
│ + name: str                     ├──────────>│ + endpoint_id: int (FK)                │
│ + url: str                      │           │ + endpoint_name: str                   │
│ + method: str (GET/POST/PUT)    │           │ + endpoint_url: str                    │
│ + auth_type: str (none/bearer)  │           │ + score: int (0..100)                  │
│ + auth_value: str               │           │ + risk_level: str (LOW/MEDIUM/HIGH)    │
│ + created_at: str               │           │ + total_tests: int                     │
└─────────────────────────────────┘           │ + passed_tests: int                    │
                                              │ + failed_tests: int                    │
                                              │ + warn_tests: int                      │
                                              │ + findings_json: str                   │
                                              │ + created_at: str                      │
                                              └────────────────────────────────────────┘
```

> **Note for Draw.io:** These diagrams can be directly imported or visualized in Draw.io using standard UML and flowchart shape libraries.
