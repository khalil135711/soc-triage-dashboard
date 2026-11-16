import os
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

import pytest
from fastapi.testclient import TestClient

from app.enrichment import enrich
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def auth(client, user="analyst", pw="analyst123"):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


ALERT = {"timestamp": "2026-11-16T10:00:00Z", "source_ip": "203.0.113.5",
         "dest_ip": "10.0.0.4", "signature": "SSH brute force attempt", "severity": "high"}


def test_login_wrong_password(client):
    r = client.post("/api/auth/login", json={"username": "analyst", "password": "falsch"})
    assert r.status_code == 401


def test_requires_auth(client):
    assert client.get("/api/alerts").status_code == 401


def test_create_and_get_alert(client):
    h = auth(client)
    r = client.post("/api/alerts", json=ALERT, headers=h)
    assert r.status_code == 201
    body = r.json()
    assert body["mitre_id"] == "T1110"
    assert 0 <= body["score"] <= 100
    assert client.get(f"/api/alerts/{body['id']}", headers=h).status_code == 200


def test_invalid_ip_rejected(client):
    h = auth(client)
    r = client.post("/api/alerts", json={**ALERT, "source_ip": "not-an-ip"}, headers=h)
    assert r.status_code == 422


def test_status_change_and_note(client):
    h = auth(client)
    a = client.post("/api/alerts", json=ALERT, headers=h).json()
    r = client.patch(f"/api/alerts/{a['id']}", json={"status": "investigating"}, headers=h)
    assert r.json()["status"] == "investigating"
    n = client.post(f"/api/alerts/{a['id']}/notes", json={"text": "Logs prüfen"}, headers=h)
    assert n.status_code == 201


def test_filter_and_stats(client):
    h = auth(client)
    assert client.get("/api/alerts?severity=high&status=new", headers=h).status_code == 200
    assert client.get("/api/stats", headers=h).json()["total"] >= 1


def test_sort_injection_blocked(client):
    h = auth(client)
    r = client.get("/api/alerts?sort=score;DROP TABLE alerts", headers=h)
    assert r.status_code == 422


def test_delete_requires_admin(client):
    h = auth(client)
    a = client.post("/api/alerts", json=ALERT, headers=h).json()
    assert client.delete(f"/api/alerts/{a['id']}", headers=h).status_code == 403
    admin = auth(client, "admin", "admin123")
    assert client.delete(f"/api/alerts/{a['id']}", headers=admin).status_code == 204


def test_enrichment_scores():
    low = enrich("Random info", "low", "10.0.0.1")
    high = enrich("Ransomware activity", "critical", "8.8.8.8")
    assert high["score"] > low["score"]
    assert high["mitre_id"] == "T1486"
