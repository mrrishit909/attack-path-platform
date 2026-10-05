"""Public API (modular monolith). Blueprint services map to: collector-manager + normalizer + graph-writer (sync job),
attack-path-engine and remediation-simulator (ap/graph.py), query-copilot (ap/query.py), web-api (this file).

    uvicorn ap.api:app          python -m core.jobs ap.api      # the worker
"""
import datetime
import json
import os
import time
import uuid

from cryptography.fernet import Fernet
from fastapi import Depends, Header
from fastapi.encoders import jsonable_encoder
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from core import audit, db, jobs
from core.app import Ctx, Problem, create_app, run

from . import estate, graph, normalize, query, store

READ = {"graph:read", "simulate", "query", "jobs:read"}
PERMISSIONS = {"analyst": READ, "admin": READ | {"integrations:write", "sync", "remediations:write", "audit:read"}}
app = create_app("attack-path-platform", PERMISSIONS)
auth = app.state.auth
IdemKey = Header(None, alias="Idempotency-Key")
EFFORT = {1: "low", 2: "medium", 3: "high"}
_cache = {}      # tenant_id -> (snapshot_id, world, analysis)


def utcnow():
    return datetime.datetime.now(datetime.UTC)


def fernet():
    return Fernet(os.environ["SECRETS_KEY"])


def latest_snapshot(c):
    snap = c.execute("SELECT * FROM graph_snapshots ORDER BY generated_at DESC LIMIT 1").fetchone()
    if not snap:
        raise Problem(409, "no_snapshot", "register integrations and run a sync first")
    return snap


def current(c, ctx):
    """The tenant's graph and its analysis for the latest snapshot, built once per process and snapshot."""
    snap = latest_snapshot(c)
    hit = _cache.get(ctx.tenant_id)
    if not hit or hit[0] != snap["id"]:
        world = store.load_world(c)
        hit = _cache[ctx.tenant_id] = (snap["id"], world, graph.analyze(world))
    return snap, hit[1], hit[2]


def node_view(world, key):
    n = world["nodes"][key]
    return {"key": key, "id": n.get("id"), "name": n["name"], "type": n["type"], "provider": n["provider"], "criticality": n["criticality"]}


def path_view(world, p):
    return {"signature": p["signature"], "risk_score": p["risk_score"], "probability": round(p["probability"], 4), "target": world["nodes"][p["target"]]["name"],
            "hops": len(p["edges"]), "techniques": p["techniques"], "nodes": [node_view(world, k) for k in p["nodes"]],
            "edges": [{"type": e["type"], "p": round(e["p"], 3), "technique": e["technique"], "detail": e["detail"], "remediation": e["remediation"]} for e in p["edges"]]}


def describe(world, ref):
    """A remediation id in words, with the team that owns the thing to change."""
    kind, *parts = ref.split("|")
    name = lambda k: world["nodes"][k]["name"] if k in world["nodes"] else k      # noqa: E731
    owner = lambda *keys: next((world["nodes"][k]["attributes"].get("owner") for k in keys if k in world["nodes"] and world["nodes"][k]["attributes"].get("owner")), "identity-team")  # noqa: E731
    if kind == "patch":
        return {"type": "patch_vulnerability", "title": f"Patch {parts[1]} on {name(parts[0])}", "owner": owner(parts[0])}
    if kind == "mfa":
        return {"type": "enforce_mfa", "title": f"Enforce multi-factor sign-in for {name(parts[0])}", "owner": "identity-team"}
    return {"type": "remove_permission", "title": f"Remove {parts[1]} from {name(parts[0])} to {name(parts[2])}", "owner": owner(parts[2], parts[0])}


# ---------------------------------------------------------------- collector-manager

class IntegrationIn(BaseModel):
    provider: str = Field(pattern="^(aws|azure|entra)$")
    credentials: dict = Field(description="Stored encrypted. For the built-in simulator: {\"simulator\": {\"scale\": 1.0, \"seed\": 11}}")


@app.post("/v1/integrations", status_code=201, tags=["collectors"], summary="Register a cloud / identity source (read-only collection)")
def add_integration(body: IntegrationIn, ctx: Ctx = Depends(auth("integrations:write")), idem: str | None = IdemKey):
    def work(c):
        sim = body.credentials.get("simulator")
        if not isinstance(sim, dict) or not 0 < float(sim.get("scale", 0)) <= 2:
            raise Problem(422, "unsupported_credentials", "this build only has the simulated collector: pass {\"simulator\": {\"scale\": 0-2, \"seed\": int}}")
        iid = c.execute("""INSERT INTO integrations (id, tenant_id, provider, encrypted_credentials) VALUES (%s,%s,%s,%s)
                           ON CONFLICT (tenant_id, provider) DO UPDATE SET encrypted_credentials = excluded.encrypted_credentials RETURNING id""",
                        [uuid.uuid7(), ctx.tenant_id, body.provider, Jsonb({"ciphertext": fernet().encrypt(json.dumps(body.credentials).encode()).decode()})]).fetchone()["id"]
        audit.record(c, ctx, "integration.registered", "integration", iid, {"provider": body.provider})
        return 201, {"id": iid, "provider": body.provider, "mode": "read-only simulator", "last_sync_at": None}
    return run(ctx, idem, body, work)


@app.post("/v1/syncs", status_code=202, tags=["collectors"], summary="Collect, normalize, write the graph and compute attack paths (job)")
def start_sync(ctx: Ctx = Depends(auth("sync")), idem: str | None = IdemKey):
    def work(c):
        if not c.execute("SELECT 1 FROM integrations LIMIT 1").fetchone():
            raise Problem(409, "no_integrations", "register at least one integration first")
        return 202, jobs.enqueue(c, ctx, "sync.run", {})
    return run(ctx, idem, {}, work)


@jobs.handler("sync.run")
def sync(c, job):
    t0, now, tenant_id = time.perf_counter(), utcnow(), job["tenant_id"]
    fixed = frozenset(r["target_ref"] for r in c.execute("SELECT target_ref FROM remediations WHERE status = 'done'"))
    snaps, watermark = {}, {}
    for i in c.execute("SELECT id, provider, encrypted_credentials FROM integrations ORDER BY provider").fetchall():
        sim = json.loads(fernet().decrypt(i["encrypted_credentials"]["ciphertext"].encode()))["simulator"]
        snaps[i["provider"]] = estate.build(float(sim["scale"]), int(sim.get("seed", 11)), fixed)[0][i["provider"]]      # the simulated collector
        watermark[i["provider"]] = now.isoformat()
        c.execute("UPDATE integrations SET last_sync_at = %s WHERE id = %s", [now, i["id"]])
    world = normalize.merge(snaps)
    t1 = time.perf_counter()
    store.write_world(c, tenant_id, world, now)
    world = store.load_world(c)          # analyse exactly what was stored
    t2 = time.perf_counter()
    a = graph.analyze(world)
    best = graph.optimize(world, budget=2)
    t3 = time.perf_counter()
    kinds = {}
    for n in world["nodes"].values():
        kinds[n["type"]] = kinds.get(n["type"], 0) + 1
    jewels = sorted(({"asset_id": world["nodes"][t]["id"], "name": world["nodes"][t]["name"], "provider": world["nodes"][t]["provider"],
                      "owner": world["nodes"][t]["attributes"].get("owner"), "risk": r, "paths": sum(p["target"] == t for p in a["paths"])}
                     for t, r in a["by_target"].items()), key=lambda j: (-j["risk"], j["name"]))
    summary = {"engine": graph.VERSION, "nodes": kinds, "relationships": len(world["rels"]), "open_findings": len(world["vulns"]),
               "kev_findings": sum(v["kev"] for v in world["vulns"]), "dangling_references": 0, "risk_index": a["risk"],
               "crown_jewels": len(jewels), "crown_jewels_exposed": a["exposed_targets"], "attack_paths": len(a["paths"]),
               "mean_path_risk": round(sum(p["risk_score"] for p in a["paths"]) / max(1, len(a["paths"])), 2), "targets": jewels,
               "best_two_fixes": {"risk_after": best["risk_after"], "chosen": [{"ref": r, **describe(world, r)} for r in best["chosen"]]},
               "timings_ms": {"collect_normalize": round(1000 * (t1 - t0)), "write_and_reload": round(1000 * (t2 - t1)), "search_and_optimize": round(1000 * (t3 - t2))}}
    summary = jsonable_encoder(summary)
    sid = uuid.uuid7()
    c.execute("INSERT INTO graph_snapshots (id, tenant_id, generated_at, source_watermark, summary) VALUES (%s,%s,%s,%s,%s)", [sid, tenant_id, now, Jsonb(watermark), Jsonb(summary)])
    db.many(c, "INSERT INTO attack_paths (id, snapshot_id, start_node, target_node, risk_score, path_json, mitre_techniques, signature, probability) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            [(uuid.uuid7(), sid, p["nodes"][0], p["target"], p["risk_score"], Jsonb(jsonable_encoder(path_view(world, p))), p["techniques"], p["signature"], p["probability"]) for p in a["paths"]])
    c.execute("DELETE FROM remediations WHERE status = 'open'")          # the backlog is re-derived from each snapshot
    for b in graph.backlog(world, a):
        d = describe(world, b["remediation"])
        c.execute("""INSERT INTO remediations (id, tenant_id, remediation_type, target_ref, estimated_effort, risk_reduction, detail) VALUES (%s,%s,%s,%s,%s,%s,%s)
                     ON CONFLICT (tenant_id, target_ref) DO UPDATE SET risk_reduction = excluded.risk_reduction, detail = excluded.detail, updated_at = now()""",
                  [uuid.uuid7(), tenant_id, d["type"], b["remediation"], EFFORT[b["effort"]], b["risk_reduction"], Jsonb({**d, "paths_cut": b["paths_cut"]})])
    _cache.pop(tenant_id, None)
    ctx = Ctx(tenant_id, uuid.UUID(job["payload"]["actor_id"]), "worker", "system")
    audit.record(c, ctx, "snapshot.created", "graph_snapshot", sid, {"engine": graph.VERSION, "risk_index": a["risk"], "attack_paths": len(a["paths"]), "fixes_applied": len(fixed)})
    return {"snapshot_id": str(sid), **summary}


# ---------------------------------------------------------------- web-api: reads

@app.get("/v1/summary", tags=["exposure"], summary="North-star metrics and crown jewels for the latest snapshot")
def summary(ctx: Ctx = Depends(auth("graph:read"))):
    with db.tx(ctx.tenant_id) as c:
        snap = latest_snapshot(c)
        return jsonable_encoder({"snapshot_id": snap["id"], "generated_at": snap["generated_at"], **snap["summary"]})


@app.get("/v1/assets", tags=["exposure"], summary="Find assets by exact name")
def find_assets(name: str, ctx: Ctx = Depends(auth("graph:read"))):
    with db.tx(ctx.tenant_id) as c:
        return jsonable_encoder({"items": c.execute("SELECT id, name, asset_type, provider, criticality FROM assets WHERE lower(name) = lower(%s) LIMIT 20", [name]).fetchall()})


@app.get("/v1/assets/{asset_id}", tags=["exposure"], summary="Asset details and exposure context")
def asset(asset_id: uuid.UUID, ctx: Ctx = Depends(auth("graph:read"))):
    with db.tx(ctx.tenant_id) as c:
        a = c.execute("SELECT * FROM assets WHERE id = %s", [asset_id]).fetchone()
        if not a:
            raise Problem(404, "asset_not_found")
        snap, world, analysis = current(c, ctx)
        vulns = c.execute("""SELECT v.cve, v.cvss, v.kev, v.exploit_maturity, av.state FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id = av.vulnerability_id
                              WHERE av.asset_id = %s ORDER BY v.cvss DESC""", [asset_id]).fetchall()
        key = a["external_id"]
        inbound = [{"from": world["nodes"][r["src"]]["name"], "type": r["type"]} for r in world["rels"] if r["dst"] == key]
        return jsonable_encoder({**{k: a[k] for k in ("id", "name", "asset_type", "provider", "external_id", "criticality", "attributes", "first_seen", "last_seen")},
                                 "vulnerabilities": vulns, "inbound_relationships": inbound, "exposure": {
                                     "reachable_from_internet": analysis["by_target"].get(key, 0) > 0, "risk": analysis["by_target"].get(key, 0),
                                     "attack_paths": sum(p["target"] == key for p in analysis["paths"]), "snapshot_id": snap["id"]}})


@app.get("/v1/attack-paths", tags=["exposure"], summary="Ranked attack paths to a target asset (or across the estate)")
def attack_paths(target: uuid.UUID | None = None, limit: int = 10, ctx: Ctx = Depends(auth("graph:read"))):
    with db.tx(ctx.tenant_id) as c:
        snap, key = latest_snapshot(c), None
        if target:
            a = c.execute("SELECT external_id FROM assets WHERE id = %s", [target]).fetchone()
            if not a:
                raise Problem(404, "asset_not_found")
            key = a["external_id"]
        rows = c.execute("""SELECT id, risk_score, path_json FROM attack_paths WHERE snapshot_id = %s AND (%s::text IS NULL OR target_node = %s)
                             ORDER BY risk_score DESC LIMIT %s""", [snap["id"], key, key, max(1, min(limit, 100))]).fetchall()
        total = c.execute("SELECT count(*) AS n FROM attack_paths WHERE snapshot_id = %s AND (%s::text IS NULL OR target_node = %s)", [snap["id"], key, key]).fetchone()["n"]
    return jsonable_encoder({"snapshot_id": snap["id"], "engine": snap["summary"]["engine"], "total": total, "paths": [{"id": r["id"], **r["path_json"]} for r in rows]})


@app.get("/v1/changes", tags=["exposure"], summary="High-risk paths that appeared or disappeared between the last two snapshots")
def changes(ctx: Ctx = Depends(auth("graph:read"))):
    with db.tx(ctx.tenant_id) as c:
        snaps = c.execute("SELECT id, generated_at, summary FROM graph_snapshots ORDER BY generated_at DESC LIMIT 2").fetchall()
        if len(snaps) < 2:
            raise Problem(409, "need_two_snapshots", "changes compare the latest snapshot with the one before it")
        paths = {s["id"]: {r["signature"]: r for r in c.execute("SELECT signature, risk_score, path_json FROM attack_paths WHERE snapshot_id = %s", [s["id"]])} for s in snaps}
    new, old = paths[snaps[0]["id"]], paths[snaps[1]["id"]]
    brief = lambda r: {"risk_score": r["risk_score"], "target": r["path_json"]["target"], "route": " > ".join(n["name"] for n in r["path_json"]["nodes"])}   # noqa: E731
    return jsonable_encoder({"from": {"snapshot_id": snaps[1]["id"], "at": snaps[1]["generated_at"], "risk_index": snaps[1]["summary"]["risk_index"], "attack_paths": len(old)},
                             "to": {"snapshot_id": snaps[0]["id"], "at": snaps[0]["generated_at"], "risk_index": snaps[0]["summary"]["risk_index"], "attack_paths": len(new)},
                             "removed": sorted((brief(old[s]) for s in old.keys() - new.keys()), key=lambda b: -b["risk_score"]),
                             "added": sorted((brief(new[s]) for s in new.keys() - old.keys()), key=lambda b: -b["risk_score"])})


# ---------------------------------------------------------------- remediation-simulator

class SimulationIn(BaseModel):
    remediations: list[str] | None = Field(None, max_length=50, description="Remediation ids to apply hypothetically. Omit to let the optimizer choose.")
    budget: int = Field(2, ge=1, le=10)
    target: uuid.UUID | None = Field(None, description="Limit the question to one crown-jewel asset")


@app.post("/v1/simulations", tags=["remediation"], summary="Apply a hypothetical remediation set (or ask for the best one) and compute the risk delta")
def simulate(body: SimulationIn, ctx: Ctx = Depends(auth("simulate"))):
    with db.tx(ctx.tenant_id) as c:
        snap, world, base = current(c, ctx)
        only = None
        if body.target:
            a = c.execute("SELECT external_id FROM assets WHERE id = %s", [body.target]).fetchone()
            if not a or a["external_id"] not in base["by_target"]:
                raise Problem(404, "target_not_found", "target must be a crown-jewel asset (criticality 5)")
            only = [a["external_id"]]
    t0 = time.perf_counter()
    before = graph.analyze(world, only=only)
    if body.remediations is None:
        opt = graph.optimize(world, body.budget, only=only)
        chosen, mode = opt["chosen"], f"optimizer ({opt['solver_status'].lower()}, {opt['paths_considered']} paths considered)"
    else:
        known = {r["remediation"] for r in world["rels"] if r["remediation"]} | {estate.remediation_id("patch", v["asset"], v["cve"]) for v in world["vulns"]}
        unknown = [r for r in body.remediations if r not in known]
        if unknown:
            raise Problem(422, "unknown_remediation", f"not present in this tenant's graph: {unknown[:3]}")
        chosen, mode = body.remediations, "as requested"
    after = graph.analyze(world, frozenset(chosen), only=only)
    naive = graph.analyze(world, frozenset(graph.baseline_cvss(world, len(chosen))), only=only)
    pct = lambda x: round(100 * (before["risk"] - x) / before["risk"], 1) if before["risk"] else 0.0      # noqa: E731
    return jsonable_encoder({
        "snapshot_id": snap["id"], "engine": graph.VERSION, "mode": mode, "scope": world["nodes"][only[0]]["name"] if only else "all crown jewels",
        "chosen": [{"ref": r, **describe(world, r)} for r in chosen],
        "risk_before": before["risk"], "risk_after": after["risk"], "risk_reduction_pct": pct(after["risk"]),
        "paths_before": len(before["paths"]), "paths_after": len(after["paths"]),
        "remaining_paths": [path_view(world, p) for p in after["paths"][:3]],
        "baseline": {"name": f"patch the {len(chosen)} highest-CVSS findings in the estate", "risk_after": naive["risk"], "risk_reduction_pct": pct(naive["risk"])},
        "compute_ms": round(1000 * (time.perf_counter() - t0), 1)})


@app.get("/v1/remediations", tags=["remediation"], summary="Prioritized backlog: verified risk reduction per unit of effort")
def remediations(ref: str | None = None, ctx: Ctx = Depends(auth("graph:read"))):
    with db.tx(ctx.tenant_id) as c:
        rows = c.execute("""SELECT id, remediation_type, target_ref, estimated_effort, risk_reduction, status, detail, updated_at FROM remediations
                             WHERE %s::text IS NULL OR target_ref = %s ORDER BY (status = 'done'), risk_reduction DESC""", [ref, ref]).fetchall()
    return jsonable_encoder({"items": rows})


def _remediation(c, rid):
    r = c.execute("SELECT * FROM remediations WHERE id = %s FOR UPDATE", [rid]).fetchone()
    if not r:
        raise Problem(404, "remediation_not_found")
    return r


@app.post("/v1/remediations/{rid}/ticket", status_code=201, tags=["remediation"], summary="Generate a remediation ticket with path evidence and owner")
def ticket(rid: uuid.UUID, ctx: Ctx = Depends(auth("remediations:write")), idem: str | None = IdemKey):
    def work(c):
        r = _remediation(c, rid)
        snap = latest_snapshot(c)
        paths = [p["path_json"] for p in c.execute("SELECT path_json FROM attack_paths WHERE snapshot_id = %s ORDER BY risk_score DESC", [snap["id"]])
                 if any(e["remediation"] == r["target_ref"] for e in p["path_json"]["edges"])]
        lines = [f"Why: this change cuts {len(paths)} attack path(s) from the internet to crown-jewel data and lowers the estate risk index by {r['risk_reduction']}.", "", "Evidence:"]
        for p in paths[:5]:
            lines.append(f"- risk {p['risk_score']}: " + " > ".join(n["name"] for n in p["nodes"]))
            lines += [f"    step {i + 1} {e['type']} ({e['technique']}){' ' + e['detail'] if e['detail'] else ''}{'   <-- this ticket' if e['remediation'] == r['target_ref'] else ''}"
                      for i, e in enumerate(p["edges"])]
        lines += ["", f"Change: {r['detail']['title']}.", f"Verify: re-run collection; the paths above must be absent from GET /v1/changes. Snapshot {snap['id']}, engine {snap['summary']['engine']}."]
        key = f"SEC-{str(rid)[-6:].upper()}"
        c.execute("UPDATE remediations SET status = 'ticketed', updated_at = now() WHERE id = %s AND status = 'open'", [rid])
        audit.record(c, ctx, "remediation.ticketed", "remediation", rid, {"ticket": key, "owner": r["detail"]["owner"], "paths": len(paths)})
        return 201, {"ticket": key, "title": r["detail"]["title"], "owner": r["detail"]["owner"], "effort": r["estimated_effort"],
                     "priority": "P1" if float(r["risk_reduction"]) >= 50 else "P2", "body": "\n".join(lines)}
    return run(ctx, idem, {}, work)


@app.post("/v1/remediations/{rid}:complete", tags=["remediation"], summary="Mark a fix as carried out; the next collection reflects it")
def complete(rid: uuid.UUID, ctx: Ctx = Depends(auth("remediations:write")), idem: str | None = IdemKey):
    def work(c):
        r = _remediation(c, rid)
        c.execute("UPDATE remediations SET status = 'done', updated_at = now() WHERE id = %s", [rid])
        audit.record(c, ctx, "remediation.completed", "remediation", rid, {"target_ref": r["target_ref"]})
        return 200, {"id": rid, "status": "done", "title": r["detail"]["title"]}
    return run(ctx, idem, {}, work)


# ---------------------------------------------------------------- query-copilot

class QueryIn(BaseModel):
    question: str = Field(min_length=5, max_length=300)


@app.post("/v1/query", tags=["query"], summary="Grounded security graph question (rule-based parser; answers carry their edges)")
def ask(body: QueryIn, ctx: Ctx = Depends(auth("query"))):
    with db.tx(ctx.tenant_id) as c:
        snap, world, analysis = current(c, ctx)
    out = query.answer(world, analysis, body.question)
    if "error" in out:
        raise Problem(422 if out["error"] == "unsupported_question" else 404, out["error"], out.get("detail") or "supported: " + "; ".join(out["supported"]))
    return jsonable_encoder({"question": body.question, "snapshot_id": snap["id"], **out})
