import os

import psycopg
import pytest

ADMIN = os.environ.get("DATABASE_URL", "postgresql://app:app-dev-only@127.0.0.1:55102/app")
os.environ.setdefault("SECRETS_KEY", "5GLLleoYnSir2JlvICy3ltIhmzeuoSgKZ6oLsJb6-Vo=")      # test-only key
os.environ["DATABASE_URL"] = ADMIN.rsplit("/", 1)[0] + "/app_test"


@pytest.fixture(scope="session")
def tenants():
    """A fresh database with both tenants; the second already has a small synced estate."""
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS app_test WITH (FORCE)")
        c.execute("CREATE DATABASE app_test")
    from ap import seed
    from core import db
    ids = seed.main()
    yield ids
    db.close()


@pytest.fixture(scope="session")
def client(tenants):
    from fastapi.testclient import TestClient

    from ap.api import app
    return TestClient(app)


def bearer(tenant, role):
    return {"Authorization": f"Bearer {tenant}-{role}-demo"}
