from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    r=client.get("/api/health")
    assert r.status_code==200
    assert r.json()["status"]=="ok"

def test_assets_and_vulnerabilities():
    assert client.get("/api/assets").status_code==200
    assert len(client.get("/api/assets").json())>=1
    assert len(client.get("/api/vulnerabilities").json())>=1

def test_simulation_reproducible():
    a=client.get("/api/simulate?degradation=0.3&scenarios=20&seed=7").json()
    b=client.get("/api/simulate?degradation=0.3&scenarios=20&seed=7").json()
    assert a["results"]==b["results"]

def test_topk_probability_bounds():
    x=client.get("/api/simulate?degradation=0.2&scenarios=20&seed=1").json()
    assert all(0<=r["top_k_probability"]<=1 for r in x["results"])

def test_rankings():
    x=client.get("/api/rankings").json()
    assert {"cvss","epss","kev","combined","assetwise"} <= set(x)
