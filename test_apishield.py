"""
test_apishield.py — Simple, clean pytest test suite for APIShield.
Demonstrates:
- Unit & integration testing of security functions
- Validation of vulnerability detection against the demo APIs
"""
import pytest
from fastapi.testclient import TestClient
from app import app, get_db

client = TestClient(app)

def test_root_serves_html():
    """Verify that visiting '/' returns the APIShield web dashboard."""
    response = client.get("/")
    assert response.status_code == 200
    assert "APIShield" in response.text

def test_endpoints_crud():
    """Verify that adding, listing, and deleting endpoints works."""
    # 1. Add endpoint
    new_ep = {
        "name": "Pytest Mock API",
        "url": "http://127.0.0.1:8000/demo/vulnerable/notes",
        "method": "GET",
        "auth_type": "none",
        "auth_value": ""
    }
    create_res = client.post("/api/endpoints", json=new_ep)
    assert create_res.status_code == 200
    ep_id = create_res.json()["id"]

    # 2. List endpoints
    list_res = client.get("/api/endpoints")
    assert list_res.status_code == 200
    endpoints = list_res.json()
    assert any(ep["id"] == ep_id for ep in endpoints)

    # 3. Clean up
    del_res = client.delete(f"/api/endpoints/{ep_id}")
    assert del_res.status_code == 200

def test_vulnerable_endpoint_behavior():
    """Verify vulnerable endpoint permits unauthenticated access."""
    res = client.get("/demo/vulnerable/notes")
    assert res.status_code == 200
    assert "notes" in res.json()

def test_secure_endpoint_requires_auth():
    """Verify secure endpoint rejects unauthenticated requests with HTTP 401."""
    res = client.get("/demo/secure/notes")
    assert res.status_code == 401
    assert "Authentication Required" in res.json()["detail"]

def test_secure_endpoint_with_auth_and_headers():
    """Verify secure endpoint accepts valid token and returns security headers."""
    headers = {"Authorization": "Bearer secret-token-123"}
    res = client.get("/demo/secure/notes", headers=headers)
    assert res.status_code == 200
    assert "notes" in res.json()
    # Check defense-in-depth headers
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"

def test_scan_vulnerable_endpoint():
    """Verify scanner flags broken authentication on the vulnerable demo endpoint."""
    # Seed or fetch vulnerable endpoint ID
    conn = get_db()
    row = conn.execute("SELECT id FROM endpoints WHERE name LIKE '%Vulnerable%' LIMIT 1").fetchone()
    conn.close()
    assert row is not None, "Vulnerable demo endpoint must be seeded in SQLite"
    vuln_id = row["id"]

    scan_res = client.post(f"/api/scan/{vuln_id}")
    assert scan_res.status_code == 200
    data = scan_res.json()
    
    # Must have detected Broken Authentication
    findings = data["findings"]
    auth_finding = next((f for f in findings if f["test_name"] == "Broken Authentication"), None)
    assert auth_finding is not None
    assert auth_finding["status"] == "FAIL"
    assert auth_finding["severity"] == "CRITICAL"
    
    # Score should be degraded due to vulnerabilities
    assert data["summary"]["score"] <= 60
    assert data["summary"]["risk_level"] in ["MEDIUM", "HIGH"]

def test_scan_secure_endpoint():
    """Verify scanner passes the secure demo endpoint with a high score."""
    conn = get_db()
    row = conn.execute("SELECT id FROM endpoints WHERE name LIKE '%Secure%' LIMIT 1").fetchone()
    conn.close()
    assert row is not None, "Secure demo endpoint must be seeded in SQLite"
    sec_id = row["id"]

    scan_res = client.post(f"/api/scan/{sec_id}")
    assert scan_res.status_code == 200
    data = scan_res.json()

    # Broken Authentication should PASS because it rejected request without credentials
    findings = data["findings"]
    auth_finding = next((f for f in findings if f["test_name"] == "Broken Authentication"), None)
    assert auth_finding is not None
    assert auth_finding["status"] == "PASS"

    # Score should be high (>= 80)
    assert data["summary"]["score"] >= 80
    assert data["summary"]["risk_level"] == "LOW"
