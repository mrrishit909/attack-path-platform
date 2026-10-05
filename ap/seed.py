"""Tenants and demo tokens, plus a small synced estate for the second tenant (isolation tests need something to protect).

    python -m ap.seed [--if-empty]
"""
import hashlib
import json
import sys
import uuid

from psycopg.types.json import Jsonb

from core import db, jobs
from core.app import Ctx

TENANTS = {"acme": "Acme Retail Group", "other": "Second Tenant Ltd"}
ROLES = ["analyst", "admin"]


def token(tenant, role):
    """Demo credentials for local use only."""
    return f"{tenant}-{role}-demo"


def main(if_empty=False):
    from . import api
    db.migrate()
    with db.tx() as c:
        if if_empty and c.execute("SELECT 1 FROM tenants LIMIT 1").fetchone():
            return print("already seeded")
        ids = {}
        for short, name in TENANTS.items():
            ids[short] = uuid.uuid5(uuid.NAMESPACE_DNS, f"{short}.attack-path.example")
            c.execute("INSERT INTO tenants (id, name) VALUES (%s,%s)", [ids[short], name])
            for role in ROLES:
                c.execute("INSERT INTO api_tokens VALUES (%s,%s,%s,%s,%s)",
                          [hashlib.sha256(token(short, role).encode()).hexdigest(), ids[short], uuid.uuid5(ids[short], role), f"{role} ({name})", role])
    ctx = Ctx(ids["other"], uuid.uuid5(ids["other"], "admin"), "seed", "admin")
    with db.tx(ctx.tenant_id) as c:
        for provider in ("aws", "azure", "entra"):
            c.execute("INSERT INTO integrations (id, tenant_id, provider, encrypted_credentials) VALUES (%s,%s,%s,%s)",
                      [uuid.uuid7(), ctx.tenant_id, provider, Jsonb({"ciphertext": api.fernet().encrypt(json.dumps({"simulator": {"scale": 0.03, "seed": 5}}).encode()).decode()})])
        jobs.enqueue(c, ctx, "sync.run", {})
    jobs.drain()
    print("seeded tenants:", ", ".join(TENANTS.values()), "| demo tokens:", ", ".join(token(t, r) for t in TENANTS for r in ROLES))
    return ids


if __name__ == "__main__":
    main("--if-empty" in sys.argv)
