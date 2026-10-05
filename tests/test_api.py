"""Integration, end-to-end, security and failure tests against a real Postgres."""
import pytest

from core import db, jobs, scenario

from .conftest import bearer

ADMIN, ANALYST, OTHER = bearer("acme", "admin"), bearer("acme", "analyst"), bearer("other", "admin")


@pytest.fixture(scope="module")
def demo(client):
    results, _ = scenario.run(client, drain=jobs.drain)
    return results


def test_demo_journey_end_to_end(demo):
    s = demo["sync"]["result"]
    assert s["nodes"]["workload"] > 5000 and s["nodes"]["user"] > 2500 and s["crown_jewels"] >= 10 and s["attack_paths"] >= 9
    assert demo["asset"]["criticality"] == 5 and demo["asset"]["exposure"]["reachable_from_internet"]
    top = demo["paths"]["paths"][0]
    assert [n["name"] for n in top["nodes"]] == ["Internet", "web-frontend", "web-frontend-role", "deploy-automation", "prod/db/orders-master", "orders-db"]
    assert [e["type"] for e in top["edges"]] == ["EXPOSED_TO", "RUNS_AS", "CAN_ASSUME", "CAN_READ", "GRANTS"] and "KEV" in top["edges"][0]["detail"]
    assert demo["paths"]["total"] == 4 and len(demo["paths"]["paths"]) == 3
    assert "deploy-automation" in demo["q1"]["answer"] and demo["q1"]["facts"]
    assert "ops-kv/aws-deploy-key" in demo["q2"]["answer"]
    sim = demo["sim"]
    assert {c["type"] for c in sim["chosen"]} == {"remove_permission", "patch_vulnerability"} and sim["risk_reduction_pct"] > 90
    assert sim["baseline"]["risk_reduction_pct"] == 0
    assert demo["sim_estate"]["risk_after"] < demo["sim_estate"]["risk_before"]
    assert demo["sim8"]["risk_reduction_pct"] > demo["sim8"]["baseline"]["risk_reduction_pct"] + 50
    assert "<-- this ticket" in demo["ticket"]["body"] and demo["ticket"]["owner"] == "payments-team"
    ch = demo["changes"]
    assert ch["to"]["risk_index"] < ch["from"]["risk_index"] and len(ch["removed"]) >= 3 and ch["added"] == []
    assert all("orders-db" == r["target"] for r in ch["removed"])
    assert demo["audit"]["chain_valid"] and {"snapshot.created", "remediation.ticketed", "remediation.completed"} <= {e["action"] for e in demo["audit"]["events"]}


def test_resync_is_idempotent(client, demo):
    with db.tx() as c:
        before = c.execute("SELECT (SELECT count(*) FROM assets) a, (SELECT count(*) FROM identities) i, (SELECT count(*) FROM relationships WHERE removed_at IS NULL) r").fetchone()
    job = client.post("/v1/syncs", headers=ADMIN).json()
    jobs.drain()
    assert client.get(job["status_url"], headers=ADMIN).json()["status"] == "succeeded"
    with db.tx() as c:
        after = c.execute("SELECT (SELECT count(*) FROM assets) a, (SELECT count(*) FROM identities) i, (SELECT count(*) FROM relationships WHERE removed_at IS NULL) r").fetchone()
        closed = c.execute("SELECT count(*) AS n FROM relationships WHERE removed_at IS NOT NULL").fetchone()["n"]
    assert before == after and closed >= 1                                       # the revoked permission is kept as history, not deleted
    ch = client.get("/v1/changes", headers=ANALYST).json()
    assert ch["removed"] == [] and ch["added"] == []


@pytest.mark.parametrize("headers,method,path,expected", [
    ({}, "GET", "/v1/summary", 401),
    (ANALYST, "POST", "/v1/syncs", 403),
    (ANALYST, "POST", "/v1/integrations", 403),
    (ANALYST, "GET", "/v1/audit", 403),
    (ANALYST, "GET", "/v1/summary", 200),
    (ADMIN, "GET", "/v1/audit", 200),
])
def test_authorization_matrix(client, demo, headers, method, path, expected):
    assert client.request(method, path, headers=headers, json={} if method == "POST" else None).status_code == expected


def test_tenant_cannot_traverse_another_tenants_graph(client, demo):
    aid = demo["found"]["items"][0]["id"]
    assert client.get(f"/v1/assets/{aid}", headers=OTHER).status_code == 404
    assert client.get(f"/v1/attack-paths?target={aid}", headers=OTHER).status_code == 404
    assert client.post("/v1/simulations", headers=OTHER, json={"target": aid}).status_code == 404
    assert client.get("/v1/assets?name=orders-db", headers=OTHER).json()["items"][0]["id"] != aid       # their own, smaller estate
    theirs = client.get("/v1/summary", headers=OTHER).json()
    assert theirs["nodes"]["workload"] < 500
    rid = demo["rem1"]["items"][0]["id"]
    assert client.post(f"/v1/remediations/{rid}/ticket", headers=OTHER).status_code == 404
    ref = next(c["ref"] for c in demo["sim"]["chosen"] if c["type"] == "patch_vulnerability")                                         # a CVE that exists only in the big estate
    assert client.post("/v1/simulations", headers=OTHER, json={"remediations": [ref]}).json()["code"] == "unknown_remediation"


def test_bad_input_is_a_problem_document(client, demo):
    r = client.post("/v1/query", headers=ANALYST, json={"question": "please write me a poem about clouds"})
    assert r.status_code == 422 and r.json()["code"] == "unsupported_question" and r.headers["content-type"].startswith("application/problem+json")
    assert client.post("/v1/query", headers=ANALYST, json={"question": "is nothing-like-this exposed to the internet"}).json()["code"] == "unknown_entity"
    assert client.post("/v1/integrations", headers=ADMIN, json={"provider": "gcp", "credentials": {}}).status_code == 422
    assert client.post("/v1/integrations", headers=ADMIN, json={"provider": "aws", "credentials": {"access_key": "x"}}).json()["code"] == "unsupported_credentials"
    assert client.post("/v1/simulations", headers=ANALYST, json={"budget": 99}).status_code == 422


def test_credentials_are_encrypted_at_rest(demo):
    with db.tx() as c:
        raw = c.execute("SELECT encrypted_credentials::text AS t FROM integrations LIMIT 1").fetchone()["t"]
    assert "simulator" not in raw and "ciphertext" in raw


def test_metrics(client, demo):
    assert 'route="/v1/simulations"' in client.get("/metrics").text
