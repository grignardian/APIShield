import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from fastapi.testclient import TestClient
from app import app, get_db

client = TestClient(app)


def test_root_serves_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "APIShield" in response.text


def test_endpoints_crud():
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

    list_res = client.get("/api/endpoints")
    assert list_res.status_code == 200
    assert any(ep["id"] == ep_id for ep in list_res.json())

    updated_ep = {
        "name": "Pytest Mock API Updated",
        "url": "http://127.0.0.1:8000/demo/secure/notes",
        "method": "POST",
        "auth_type": "bearer",
        "auth_value": "secret-token-123"
    }
    update_res = client.put(f"/api/endpoints/{ep_id}", json=updated_ep)
    assert update_res.status_code == 200

    list_after = client.get("/api/endpoints").json()
    matched = next(ep for ep in list_after if ep["id"] == ep_id)
    assert matched["name"] == "Pytest Mock API Updated"
    assert matched["method"] == "POST"

    del_res = client.delete(f"/api/endpoints/{ep_id}")
    assert del_res.status_code == 200


def test_vulnerable_endpoint_behavior():
    res = client.get("/demo/vulnerable/notes")
    assert res.status_code == 200
    assert "notes" in res.json()


def test_secure_endpoint_requires_auth():
    res = client.get("/demo/secure/notes")
    assert res.status_code == 401
    assert "Authentication Required" in res.json()["detail"]


def test_secure_endpoint_with_auth_and_headers():
    headers = {"Authorization": "Bearer secret-token-123"}
    res = client.get("/demo/secure/notes", headers=headers)
    assert res.status_code == 200
    assert "notes" in res.json()
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"


def test_scan_vulnerable_endpoint():
    conn = get_db()
    row = conn.execute("SELECT id FROM endpoints WHERE name LIKE '%Vulnerable%' LIMIT 1").fetchone()
    conn.close()
    assert row is not None
    vuln_id = row["id"]

    scan_res = client.post(f"/api/scan/{vuln_id}")
    assert scan_res.status_code == 200
    data = scan_res.json()

    auth_finding = next((f for f in data["findings"] if f["test_name"] == "Broken Authentication"), None)
    assert auth_finding is not None
    assert auth_finding["status"] == "FAIL"
    assert auth_finding["severity"] == "CRITICAL"
    assert data["summary"]["score"] <= 60
    assert data["summary"]["risk_level"] in ["MEDIUM", "HIGH"]


def test_scan_secure_endpoint():
    conn = get_db()
    row = conn.execute("SELECT id FROM endpoints WHERE name LIKE '%Secure%' LIMIT 1").fetchone()
    conn.close()
    assert row is not None
    sec_id = row["id"]

    scan_res = client.post(f"/api/scan/{sec_id}")
    assert scan_res.status_code == 200
    data = scan_res.json()

    auth_finding = next((f for f in data["findings"] if f["test_name"] == "Broken Authentication"), None)
    assert auth_finding is not None
    assert auth_finding["status"] == "PASS"
    assert data["summary"]["score"] >= 80
    assert data["summary"]["risk_level"] == "LOW"


def test_scan_nonexistent_endpoint_returns_404():
    fake_ep = {
        "name": "Fake Endpoint",
        "url": "http://127.0.0.1:8000/demo/does-not-exist",
        "method": "GET",
        "auth_type": "none",
        "auth_value": ""
    }
    ep_id = client.post("/api/endpoints", json=fake_ep).json()["id"]
    try:
        scan_res = client.post(f"/api/scan/{ep_id}")
        assert scan_res.status_code == 404
        assert "does not exist" in scan_res.json()["detail"].lower()
    finally:
        client.delete(f"/api/endpoints/{ep_id}")
