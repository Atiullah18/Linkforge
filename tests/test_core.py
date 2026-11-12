import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi.testclient import TestClient
from app.core import Bloom, LRU, b62, b62decode, scramble, SPACE
from app.main import app

c = TestClient(app, follow_redirects=False)


def test_scramble_is_unique_and_encoding_roundtrips():
    codes = {b62(scramble(i)) for i in range(20000)}
    assert len(codes) == 20000 and all(len(x) == 7 for x in codes)
    assert b62decode(b62(123456789)) == 123456789 and scramble(5) < SPACE


def test_bloom_no_false_negatives():
    b = Bloom(1000)
    for i in range(1000):
        b.add(f"k{i}")
    assert all(f"k{i}" in b for i in range(1000))


def test_lru_evicts_oldest():
    l = LRU(2); l.put("a", 1); l.put("b", 2); l.get("a"); l.put("c", 3)
    assert l.get("b") is None and l.get("a") == 1


def test_create_redirect_stats_delete():
    r = c.post("/api/links", json={"url": "example.com/page", "alias": "demo-1"}).json()
    assert r["code"] == "demo-1"
    g = c.get("/demo-1", headers={"user-agent": "Mozilla/5.0 Chrome/120 Mobile"})
    assert g.status_code == 302 and g.headers["location"] == "https://example.com/page"
    s = c.get("/api/links/demo-1/stats", headers={"x-owner-token": r["token"]}).json()
    assert s["clicks"] == 1 and s["devices"][0][0] == "Mobile"
    assert c.get("/api/links/demo-1/stats").status_code == 404
    assert c.post("/api/links", json={"url": "x.com", "alias": "demo-1"}).status_code == 409
    assert c.delete("/api/links/demo-1", headers={"x-owner-token": r["token"]}).status_code == 200
    assert c.get("/demo-1").status_code == 404


def test_click_limit_password_and_private_hosts():
    r = c.post("/api/links", json={"url": "https://example.org", "max_clicks": 1}).json()
    assert c.get("/" + r["code"]).status_code == 302
    assert c.get("/" + r["code"]).status_code == 410
    c.post("/api/links", json={"url": "https://example.org", "password": "s3cret", "alias": "locked"})
    assert c.post("/unlock/locked", data={"password": "no"}).status_code == 401
    assert c.post("/unlock/locked", data={"password": "s3cret"}).status_code == 302
    assert c.post("/api/links", json={"url": "http://127.0.0.1:8000"}).status_code == 422
