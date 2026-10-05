"""normalizer: vendor objects -> one canonical model of nodes, relationships and vulnerability findings.

A node is keyed by its vendor id (ARN, Azure resource id, Entra object id), which is what lets a relationship
cross clouds: an Azure Key Vault secret that unlocks an AWS role is just an edge between two keys.
Each relationship that a person could remove carries a stable remediation id.
"""
from .estate import remediation_id

INTERNET = "internet"
ACTIONS = {"sts:AssumeRole": "CAN_ASSUME", "secretsmanager:GetSecretValue": "CAN_READ", "rds-db:connect": "HAS_ACCESS", "s3:GetObject": "HAS_ACCESS"}


def _node(kind, type_, provider, ext, name, criticality=1, **attrs):
    return {"key": ext, "kind": kind, "type": type_, "provider": provider, "external_id": ext, "name": name, "criticality": criticality, "attributes": attrs}


def _rel(src, type_, dst, remediation=None, **attrs):
    return {"src": src, "type": type_, "dst": dst, "remediation": remediation, "attributes": attrs}


def aws(s):
    nodes, rels, vulns = [], [], []
    for i in s["ec2"]:
        t = i["Tags"]
        nodes.append(_node("asset", "workload", "aws", i["InstanceId"], i["Name"], 2, owner=t.get("owner"), app=t.get("app"), group=t.get("asg"), public=i["PublicIp"]))
        if i["PublicIp"] and i["OpenPorts"]:
            rels.append(_rel(INTERNET, "EXPOSED_TO", i["InstanceId"], ports=i["OpenPorts"]))
        if i["IamInstanceProfile"]:
            rels.append(_rel(i["InstanceId"], "RUNS_AS", i["IamInstanceProfile"]))
        rels += [_rel(i["InstanceId"], "REACHES", dst) for dst in i["Reaches"] if dst != i["InstanceId"]]
    for r in s["iam_roles"]:
        nodes.append(_node("identity", "role", "aws", r["Arn"], r["Name"], privilege_tier=2))
        for a in r["Allows"]:
            if a["Action"] in ACTIONS:      # anything else is not an attack step in this model
                rels.append(_rel(r["Arn"], ACTIONS[a["Action"]], a["Resource"], remediation_id("revoke", r["Arn"], a["Action"], a["Resource"]), action=a["Action"]))
    for x in s["secrets"]:
        nodes.append(_node("asset", "secret", "aws", x["Arn"], x["Name"], 3, owner=x["Tags"].get("owner")))
        rels.append(_rel(x["Arn"], "GRANTS", x["Unlocks"]))
    for d in s["datastores"]:
        t = d["Tags"]
        nodes.append(_node("asset", "datastore", "aws", d["Arn"], d["Name"], int(t.get("criticality", 1)), owner=t.get("owner"), app=t.get("app"), engine=d["Engine"]))
    vulns += [{"asset": f["resource"], "cve": f["cve"], "cvss": f["cvss"], "kev": f["kev"], "maturity": f["exploit_maturity"]} for f in s["inspector_findings"]]
    return nodes, rels, vulns


def azure(s):
    nodes, rels, vulns = [], [], []
    for v in s["virtualMachines"]:
        t = v["tags"]
        nodes.append(_node("asset", "workload", "azure", v["id"], v["name"], 2, owner=t.get("owner"), app=t.get("app"), group=t.get("scaleSet"), public=v["publicIp"]))
        if v["publicIp"]:
            rels.append(_rel(INTERNET, "EXPOSED_TO", v["id"]))
        if v["managedIdentity"]:
            rels.append(_rel(v["id"], "RUNS_AS", v["managedIdentity"]))
        rels += [_rel(v["id"], "REACHES", dst) for dst in v["reaches"] if dst != v["id"]]
    for k in s["keyVaultSecrets"]:
        nodes.append(_node("asset", "secret", "azure", k["id"], k["name"], 3, owner=k["tags"].get("owner")))
        rels.append(_rel(k["id"], "GRANTS", k["unlocks"]))
        rels += [_rel(p, "CAN_READ", k["id"], remediation_id("revoke", p, "kv:get", k["id"]), action="kv:get") for p in k["accessPolicies"]]
    for d in s["sqlDatabases"]:
        t = d["tags"]
        nodes.append(_node("asset", "datastore", "azure", d["id"], d["name"], int(t.get("criticality", 1)), owner=t.get("owner"), app=t.get("app"), engine="azure-sql"))
    rels += [_rel(a["principalId"], "HAS_ACCESS", a["scope"], remediation_id("revoke", a["principalId"], a["role"], a["scope"]), action=a["role"]) for a in s["roleAssignments"]]
    vulns += [{"asset": f["resourceId"], "cve": f["cve"], "cvss": f["cvss"], "kev": f["kev"], "maturity": f["exploitMaturity"]} for f in s["defenderFindings"]]
    return nodes, rels, vulns


def entra(s):
    nodes, rels = [], []
    for u in s["users"]:
        nodes.append(_node("identity", "user", "entra", u["id"], u["userPrincipalName"], privilege_tier=3 if u["privileged"] else 1, mfa=u["mfa"]))
        if not u["mfa"]:        # password-only sign-in is reachable from anywhere
            rels.append(_rel(INTERNET, "PHISHABLE", u["id"], remediation_id("mfa", u["id"])))
    for g in s["groups"]:
        nodes.append(_node("identity", "group", "entra", g["id"], g["displayName"], privilege_tier=1))
        rels += [_rel(m, "MEMBER_OF", g["id"]) for m in set(g["members"])]
    nodes += [_node("identity", "service_principal", "entra", p["id"], p["displayName"], privilege_tier=2) for p in s["servicePrincipals"]]
    rels += [_rel(f["principalId"], "CAN_ASSUME", f["awsRoleArn"], remediation_id("revoke", f["principalId"], "federation", f["awsRoleArn"]), action="federation") for f in s["federations"]]
    return nodes, rels, []


PROVIDERS = {"aws": aws, "azure": azure, "entra": entra}


def merge(snapshots):
    """{provider: vendor snapshot} -> canonical world. Relationships pointing at objects nobody collected are dropped and counted."""
    nodes, rels, vulns = {INTERNET: _node("internet", "internet", "any", INTERNET, "Internet", 0)}, [], []
    for provider, snap in snapshots.items():
        n, r, v = PROVIDERS[provider](snap)
        nodes.update({x["key"]: x for x in n})
        rels += r
        vulns += v
    kept = [r for r in rels if r["src"] in nodes and r["dst"] in nodes]
    return {"nodes": nodes, "rels": kept, "vulns": [v for v in vulns if v["asset"] in nodes], "dangling": len(rels) - len(kept)}
