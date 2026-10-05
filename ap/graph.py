"""attack-path-engine, remediation-simulator and the risk-reduction optimizer. Pure functions over the canonical world.

Scoring. Each attacker step has a probability of success; a path's probability is their product and its
risk score is 100 x probability x (target criticality / 5). The step probabilities are stated priors, not
fitted to incident data (there is none here): see README. Exploit steps use the easiest open vulnerability:

    p_exploit = min(0.95, 0.05 + 0.6 * (cvss / 10) * maturity + 0.25 * kev)
"""
import math
from collections import defaultdict

import networkx as nx
from ortools.sat.python import cp_model

from .estate import remediation_id
from .normalize import INTERNET

VERSION = "paths-1.0.0"
MATURITY = {"none": 0.1, "poc": 0.4, "functional": 0.75, "weaponized": 1.0}
# type: (probability, MITRE ATT&CK technique, effort to remediate; None = not something you remove)
STEPS = {
    "EXPOSED_TO": (1.0, "T1190 Exploit Public-Facing Application", 2),
    "REACHES": (0.9, "T1210 Exploitation of Remote Services", 2),
    "PHISHABLE": (0.08, "T1078.004 Valid Accounts: Cloud", 1),
    "RUNS_AS": (0.95, "T1552.005 Cloud Instance Metadata API", None),
    "MEMBER_OF": (1.0, "T1078.004 Valid Accounts: Cloud", None),
    "CAN_ASSUME": (0.9, "T1548 Abuse Elevation Control Mechanism", 1),
    "CAN_READ": (0.9, "T1555 Credentials from Password Stores", 1),
    "GRANTS": (0.95, "T1078.004 Valid Accounts: Cloud", None),
    "HAS_ACCESS": (0.9, "T1530 Data from Cloud Storage", 1),
}
K_PATHS, MAX_HOPS, EXAMINE = 8, 8, 60


def exploit_p(v):
    return min(0.95, 0.05 + 0.6 * (v["cvss"] / 10) * MATURITY[v["maturity"]] + 0.25 * v["kev"])


def attack_graph(world, removed=frozenset()):
    """Directed graph of steps an attacker could take, skipping anything in `removed` (a set of remediation ids)."""
    best = {}
    for v in world["vulns"]:
        if remediation_id("patch", v["asset"], v["cve"]) not in removed:
            p = exploit_p(v)
            if p > best.get(v["asset"], (0, None))[0]:
                best[v["asset"]] = (p, v)
    g = nx.DiGraph()
    for r in world["rels"]:
        if r["remediation"] in removed:
            continue
        p, technique, effort = STEPS[r["type"]]
        rem, detail = r["remediation"], r["attributes"].get("action", "")
        if r["type"] in ("EXPOSED_TO", "REACHES"):       # getting onto a workload needs something exploitable on it
            if r["dst"] not in best:
                continue
            ep, v = best[r["dst"]]
            p, rem = p * ep, remediation_id("patch", v["asset"], v["cve"])
            detail = f"{v['cve']} (CVSS {v['cvss']}, {v['maturity']}{', KEV' if v['kev'] else ''})"
        if not g.has_edge(r["src"], r["dst"]) or g[r["src"]][r["dst"]]["p"] < p:
            g.add_edge(r["src"], r["dst"], type=r["type"], p=p, w=-math.log(p), technique=technique, detail=detail,
                       remediation=rem if effort else None, effort=effort)
    return g


def targets(world):
    return [k for k, n in world["nodes"].items() if n["kind"] == "asset" and n["criticality"] >= 5]


def _signature(world, g, path):
    """Paths through interchangeable replicas (same autoscaling group) are one finding."""
    name = lambda k: world["nodes"][k]["attributes"].get("group") or k      # noqa: E731
    return "|".join(f"{g[a][b]['type']}>{name(b)}" for a, b in zip(path, path[1:]))


def paths_to(world, g, target, reachable, k=K_PATHS):
    if target not in reachable:
        return []
    h = g.subgraph(reachable & (nx.ancestors(g, target) | {target}))      # prune to nodes on some internet -> target route
    out, seen = [], set()
    for n, path in enumerate(nx.shortest_simple_paths(h, INTERNET, target, weight="w")):     # most probable first
        if n >= EXAMINE or len(out) >= k:
            break
        sig = _signature(world, g, path)
        if len(path) - 1 > MAX_HOPS or sig in seen:
            continue
        seen.add(sig)
        edges = [g[a][b] for a, b in zip(path, path[1:])]
        p = math.exp(-sum(e["w"] for e in edges))
        out.append({"signature": sig, "target": target, "probability": p, "risk_score": round(100 * p * world["nodes"][target]["criticality"] / 5, 2),
                    "nodes": path, "edges": edges, "techniques": sorted({e["technique"].split()[0] for e in edges}),
                    "remediations": [e["remediation"] for e in edges if e["remediation"]]})
    return out


def analyze(world, removed=frozenset(), only=None):
    """All ranked attack paths to every crown jewel, and the estate risk index (sum over targets of 100 x noisy-OR)."""
    g = attack_graph(world, removed)
    reachable = (nx.descendants(g, INTERNET) | {INTERNET}) if INTERNET in g else set()
    paths, by_target = [], {}
    for t in only or targets(world):
        found = paths_to(world, g, t, reachable) if t in g else []
        by_target[t] = round(100 * (1 - math.prod(1 - p["probability"] for p in found)), 2)
        paths += found
    paths.sort(key=lambda p: -p["risk_score"])
    return {"paths": paths, "by_target": by_target, "risk": round(sum(by_target.values()), 2),
            "exposed_targets": sum(v > 0 for v in by_target.values()), "graph": g}


def optimize(world, budget=2, rounds=4, only=None):
    """Smallest set of fixes that disconnects the most path risk: exact max-coverage (CP-SAT) over enumerated paths,
    then verified by re-running the search, because cutting the best paths can reveal ones that were below the top k."""
    known, chosen, base = {}, [], analyze(world, only=only)
    for p in base["paths"]:
        known[p["signature"]] = p
    for _ in range(rounds):
        pool = list(known.values())
        cands = sorted({r for p in pool for r in p["remediations"]})
        m = cp_model.CpModel()
        x = {r: m.NewBoolVar(r) for r in cands}
        cut = []
        for i, p in enumerate(pool):
            y = m.NewBoolVar(f"cut{i}")
            m.AddMaxEquality(y, [x[r] for r in p["remediations"]]) if p["remediations"] else m.Add(y == 0)
            cut.append(y)
        m.Add(sum(x.values()) <= budget)
        m.Maximize(sum(int(p["probability"] * 10000) * y for p, y in zip(pool, cut)))
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = 10
        solver.parameters.random_seed = 0
        solver.parameters.num_workers = 1
        status = solver.Solve(m)
        chosen = [r for r in cands if solver.Value(x[r])]
        after = analyze(world, frozenset(chosen), only=only)
        new = [p for p in after["paths"] if p["signature"] not in known]
        if not new:
            break
        for p in new:
            known[p["signature"]] = p
    return {"chosen": chosen, "risk_before": base["risk"], "risk_after": after["risk"], "solver_status": solver.StatusName(status),
            "paths_considered": len(known), "exposed_before": base["exposed_targets"], "exposed_after": after["exposed_targets"]}


def backlog(world, base, top=40):
    """Every candidate fix on a known path, ranked by verified estate-risk reduction per unit of effort."""
    cut = defaultdict(float)
    for p in base["paths"]:
        for r in set(p["remediations"]):
            cut[r] += p["probability"]
    effort = {e["remediation"]: e["effort"] for p in base["paths"] for e in p["edges"] if e["remediation"]}
    out = []
    for r in sorted(cut, key=cut.get, reverse=True)[:top * 2]:      # proxy picks the shortlist, the full search prices it
        after = analyze(world, frozenset([r]))
        out.append({"remediation": r, "risk_reduction": round(base["risk"] - after["risk"], 2), "effort": effort[r],
                    "paths_cut": sum(r in p["remediations"] for p in base["paths"])})
    return sorted(out, key=lambda b: -b["risk_reduction"] / b["effort"])[:top]


def baseline_cvss(world, k):
    """What most teams do: patch the k highest-severity findings estate-wide."""
    order = sorted(world["vulns"], key=lambda v: (-v["cvss"], -v["kev"], v["cve"]))[:k]
    return [remediation_id("patch", v["asset"], v["cve"]) for v in order]


def baseline_kev_public(world, k):
    """A smarter rule of thumb: internet-facing assets first, known-exploited before the rest, then severity."""
    public = {r["dst"] for r in world["rels"] if r["type"] == "EXPOSED_TO"}
    order = sorted((v for v in world["vulns"] if v["asset"] in public), key=lambda v: (-v["kev"], -v["cvss"], v["cve"]))[:k]
    return [remediation_id("patch", v["asset"], v["cve"]) for v in order]
