"""graph-writer: idempotent writes of the canonical world into Postgres, and the read back into memory."""
import uuid

from psycopg.types.json import Jsonb

from core import db

from .normalize import INTERNET, _node


def write_world(c, tenant_id, w, now):
    """Upsert everything seen in this collection; what was not seen is closed (relationships, findings) or removed (objects)."""
    assets = [n for n in w["nodes"].values() if n["kind"] == "asset"]
    idents = [n for n in w["nodes"].values() if n["kind"] == "identity"]
    db.many(c, """INSERT INTO assets (id, tenant_id, asset_type, provider, external_id, criticality, attributes, first_seen, last_seen, name)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (tenant_id, external_id) DO UPDATE SET last_seen = excluded.last_seen, criticality = excluded.criticality,
                                                                    attributes = excluded.attributes, name = excluded.name""",
            [(uuid.uuid7(), tenant_id, n["type"], n["provider"], n["key"], n["criticality"], Jsonb(n["attributes"]), now, now, n["name"]) for n in assets])
    c.execute("DELETE FROM assets WHERE last_seen < %s", [now])
    db.many(c, """INSERT INTO identities (id, tenant_id, identity_type, external_id, privilege_tier, attributes, name, provider, last_seen)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (tenant_id, external_id) DO UPDATE SET last_seen = excluded.last_seen, privilege_tier = excluded.privilege_tier,
                                                                    attributes = excluded.attributes, name = excluded.name""",
            [(uuid.uuid7(), tenant_id, n["type"], n["key"], n["attributes"].get("privilege_tier", 1), Jsonb(n["attributes"]), n["name"], n["provider"], now) for n in idents])
    c.execute("DELETE FROM identities WHERE last_seen < %s", [now])
    db.many(c, """INSERT INTO vulnerabilities (id, cve, cvss, kev, exploit_maturity) VALUES (%s,%s,%s,%s,%s)
                  ON CONFLICT (cve) DO UPDATE SET cvss = excluded.cvss, kev = excluded.kev, exploit_maturity = excluded.exploit_maturity""",
            [(uuid.uuid7(), v["cve"], v["cvss"], v["kev"], v["maturity"]) for v in w["vulns"]])
    asset_id = {r["external_id"]: r["id"] for r in c.execute("SELECT id, external_id FROM assets")}
    vuln_id = {r["cve"]: r["id"] for r in c.execute("SELECT id, cve FROM vulnerabilities WHERE cve = ANY(%s)", [[v["cve"] for v in w["vulns"]]])}
    db.many(c, """INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id, state, observed_at) VALUES (%s,%s,'open',%s)
                  ON CONFLICT (asset_id, vulnerability_id) DO UPDATE SET state = 'open', observed_at = excluded.observed_at""",
            [(asset_id[v["asset"]], vuln_id[v["cve"]], now) for v in w["vulns"]])
    c.execute("UPDATE asset_vulnerabilities SET state = 'fixed' WHERE observed_at < %s AND asset_id IN (SELECT id FROM assets)", [now])
    db.many(c, """INSERT INTO relationships (tenant_id, src, rel_type, dst, remediation, attributes, first_seen, last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (tenant_id, src, rel_type, dst) DO UPDATE SET last_seen = excluded.last_seen, removed_at = NULL,
                                                                           remediation = excluded.remediation, attributes = excluded.attributes""",
            [(tenant_id, r["src"], r["type"], r["dst"], r["remediation"], Jsonb(r["attributes"]), now, now) for r in w["rels"]])
    c.execute("UPDATE relationships SET removed_at = %s WHERE last_seen < %s AND removed_at IS NULL", [now, now])


def load_world(c):
    """The tenant's current graph (RLS scopes every query to the caller's tenant)."""
    nodes = {INTERNET: _node("internet", "internet", "any", INTERNET, "Internet", 0)}
    for r in c.execute("SELECT id, asset_type, provider, external_id, name, criticality, attributes FROM assets"):
        nodes[r["external_id"]] = {"key": r["external_id"], "kind": "asset", "type": r["asset_type"], "provider": r["provider"], "external_id": r["external_id"],
                                   "name": r["name"], "criticality": r["criticality"], "attributes": r["attributes"], "id": r["id"]}
    for r in c.execute("SELECT id, identity_type, provider, external_id, name, attributes FROM identities"):
        nodes[r["external_id"]] = {"key": r["external_id"], "kind": "identity", "type": r["identity_type"], "provider": r["provider"], "external_id": r["external_id"],
                                   "name": r["name"], "criticality": 0, "attributes": r["attributes"], "id": r["id"]}
    rels = [{"src": r["src"], "type": r["rel_type"], "dst": r["dst"], "remediation": r["remediation"], "attributes": r["attributes"]}
            for r in c.execute("SELECT src, rel_type, dst, remediation, attributes FROM relationships WHERE removed_at IS NULL")]
    vulns = [{"asset": r["external_id"], "cve": r["cve"], "cvss": float(r["cvss"]), "kev": r["kev"], "maturity": r["exploit_maturity"]}
             for r in c.execute("""SELECT a.external_id, v.cve, v.cvss, v.kev, v.exploit_maturity FROM asset_vulnerabilities av
                                     JOIN assets a ON a.id = av.asset_id JOIN vulnerabilities v ON v.id = av.vulnerability_id WHERE av.state = 'open'""")]
    return {"nodes": nodes, "rels": rels, "vulns": vulns, "dangling": 0}
