"""query-copilot: a small rule-based reader for security questions. No language model is involved.

It recognises a handful of question shapes, resolves names against the tenant's own graph, and answers only
with facts that are edges in that graph: every answer carries the nodes and edges it rests on. A question it
does not recognise is refused with the list of shapes it supports, never guessed at.
"""
import re

import networkx as nx

from .normalize import INTERNET

VERSION = "query-rules-1.0.0"
SHAPES = ["which identities can reach <asset>", "what can <identity or workload> reach", "is <asset> exposed to the internet",
          "which assets have <CVE id>", "how many attack paths lead to <asset>"]
PATTERNS = [
    ("identities_reaching", r"^(?:which|what) identities can (?:reach|access) (?P<x>.+?)\??$"),
    ("reach_of", r"^what can (?P<x>.+?) (?:reach|access)\??$"),
    ("exposed", r"^is (?P<x>.+?) (?:exposed to|reachable from) the internet\??$"),
    ("has_cve", r"^(?:which|what) (?:assets|workloads) (?:have|are affected by) (?P<x>cve-[\d-]+)\??$"),
    ("path_count", r"^how many (?:attack )?paths (?:lead|go) to (?P<x>.+?)\??$"),
]


def _facts(world, g, path):
    return [{"src": world["nodes"][a]["name"], "type": g[a][b]["type"], "dst": world["nodes"][b]["name"], "detail": g[a][b]["detail"]} for a, b in zip(path, path[1:])]


def answer(world, analysis, question):
    """-> dict with answer, facts (edges) and nodes; or {"error": ...} when the question or the name is not understood."""
    q = " ".join(question.lower().split())
    hit = next(((intent, m) for intent, pat in PATTERNS if (m := re.match(pat, q))), None)
    if not hit:
        return {"error": "unsupported_question", "supported": SHAPES}
    intent, m = hit
    out = _answer(world, analysis, intent, m["x"].strip(" '\""))
    if "facts" in out:      # several routes share edges: state each fact once
        out["facts"] = [f for i, f in enumerate(out["facts"]) if f not in out["facts"][:i]]
    return out


def _answer(world, analysis, intent, x):
    g = analysis["graph"]
    by_name = {n["name"].lower(): k for k, n in world["nodes"].items()}
    out = {"intent": intent, "parser": VERSION}
    if intent == "has_cve":
        hits = [v for v in world["vulns"] if v["cve"].lower() == x]
        names = sorted(world["nodes"][v["asset"]]["name"] for v in hits)
        return {**out, "answer": f"{len(names)} asset(s) have {x.upper()}: {', '.join(names) or 'none'}.",
                "facts": [{"src": world["nodes"][v["asset"]]["name"], "type": "HAS_VULNERABILITY", "dst": v["cve"], "detail": f"CVSS {v['cvss']}"} for v in hits]}
    if x not in by_name:
        return {"error": "unknown_entity", "detail": f"nothing in this tenant's graph is named '{x}'"}
    key, name = by_name[x], world["nodes"][by_name[x]]["name"]
    if intent == "exposed":
        if key in g and INTERNET in g and nx.has_path(g, INTERNET, key):
            path = nx.shortest_path(g, INTERNET, key, weight="w")
            return {**out, "answer": f"Yes. {name} is reachable from the internet in {len(path) - 1} step(s).", "facts": _facts(world, g, path)}
        return {**out, "answer": f"No attack route from the internet to {name} exists in the current snapshot.", "facts": []}
    if intent == "path_count":
        mine = [p for p in analysis["paths"] if p["target"] == key]
        return {**out, "answer": f"{len(mine)} distinct attack path(s) lead to {name}; the most likely has risk score {mine[0]['risk_score'] if mine else 0}.",
                "facts": [f for p in mine[:1] for f in _facts(world, g, p["nodes"])]}
    if key not in g:
        return {**out, "answer": f"{name} has no attack-relevant relationships in the current snapshot.", "facts": []}
    if intent == "identities_reaching":
        ids = [n for n in nx.ancestors(g, key) if world["nodes"][n]["kind"] == "identity"]
        ids.sort(key=lambda n: nx.shortest_path_length(g, n, key))
        return {**out, "answer": f"{len(ids)} identities can reach {name}: {', '.join(world['nodes'][n]['name'] for n in ids[:8])}{'…' if len(ids) > 8 else ''}.",
                "facts": [f for n in ids[:4] for f in _facts(world, g, nx.shortest_path(g, n, key))]}
    reach = [n for n in nx.descendants(g, key) if world["nodes"][n]["type"] in ("datastore", "secret")]
    reach.sort(key=lambda n: (-world["nodes"][n]["criticality"], world["nodes"][n]["name"]))
    return {**out, "answer": f"{name} can reach {len(reach)} data store(s) or secret(s): {', '.join(world['nodes'][n]['name'] for n in reach[:8])}{'…' if len(reach) > 8 else ''}.",
            "facts": [f for n in reach[:4] for f in _facts(world, g, nx.shortest_path(g, key, n))]}
