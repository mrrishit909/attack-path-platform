-- Domain model. Names follow the blueprint's persistence model; additions are marked (+).
-- The blueprint puts the graph in Neo4j. Here relationships live in Postgres and the search runs in memory
-- (networkx): at 15,000 nodes and 24,000 edges a full analysis takes about 30 ms, so a second store is not justified yet.

CREATE TABLE integrations (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, provider text NOT NULL CHECK (provider IN ('aws','azure','entra')),
  encrypted_credentials jsonb NOT NULL, last_sync_at timestamptz, UNIQUE (tenant_id, provider));
SELECT enable_tenant_rls('integrations');

CREATE TABLE assets (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, asset_type text NOT NULL, provider text NOT NULL, external_id text NOT NULL,
  criticality int NOT NULL, attributes jsonb NOT NULL, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
  name text NOT NULL,                                                                                               -- (+)
  UNIQUE (tenant_id, external_id));                           -- source-system idempotency: a re-sync updates, never duplicates
CREATE INDEX assets_name ON assets (tenant_id, lower(name));
SELECT enable_tenant_rls('assets');

CREATE TABLE vulnerabilities (id uuid PRIMARY KEY, cve text NOT NULL UNIQUE, cvss numeric NOT NULL, kev boolean NOT NULL, exploit_maturity text NOT NULL, published_at timestamptz);
CREATE TABLE asset_vulnerabilities (
  asset_id uuid REFERENCES assets ON DELETE CASCADE, vulnerability_id uuid REFERENCES vulnerabilities, state text NOT NULL, observed_at timestamptz NOT NULL,
  PRIMARY KEY (asset_id, vulnerability_id));

CREATE TABLE identities (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, identity_type text NOT NULL, external_id text NOT NULL, privilege_tier int NOT NULL,
  attributes jsonb NOT NULL, name text NOT NULL, provider text NOT NULL, last_seen timestamptz NOT NULL,           -- (+)
  UNIQUE (tenant_id, external_id));
SELECT enable_tenant_rls('identities');

CREATE TABLE relationships (                                                                                        -- (+) the graph's edges, versioned
  id bigserial PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, src text NOT NULL, rel_type text NOT NULL, dst text NOT NULL,
  remediation text, attributes jsonb NOT NULL, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL, removed_at timestamptz,
  UNIQUE (tenant_id, src, rel_type, dst));
SELECT enable_tenant_rls('relationships');

CREATE TABLE graph_snapshots (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, generated_at timestamptz NOT NULL, source_watermark jsonb NOT NULL,
  summary jsonb NOT NULL);                                                                                          -- (+)
CREATE INDEX snapshots_latest ON graph_snapshots (tenant_id, generated_at DESC);
SELECT enable_tenant_rls('graph_snapshots');

CREATE TABLE attack_paths (
  id uuid PRIMARY KEY, snapshot_id uuid NOT NULL REFERENCES graph_snapshots ON DELETE CASCADE, start_node text NOT NULL, target_node text NOT NULL,
  risk_score numeric NOT NULL, path_json jsonb NOT NULL, mitre_techniques text[] NOT NULL,
  signature text NOT NULL, probability numeric NOT NULL);                                                           -- (+)
CREATE INDEX attack_paths_target ON attack_paths (snapshot_id, target_node, risk_score DESC);

CREATE TABLE remediations (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, remediation_type text NOT NULL, target_ref text NOT NULL, estimated_effort text NOT NULL,
  risk_reduction numeric NOT NULL, status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','ticketed','done')),
  detail jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),                                             -- (+)
  UNIQUE (tenant_id, target_ref));
SELECT enable_tenant_rls('remediations');
