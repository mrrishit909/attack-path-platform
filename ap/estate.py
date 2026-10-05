"""Synthetic multi-cloud estate, emitted as three vendor-shaped snapshots (AWS, Azure, Entra ID).

These stand in for the read-only collectors. Shapes are simplified but keep each vendor's vocabulary, so the
normalizer has real work to do. Everything is invented; CVE ids use the reserved-looking prefix CVE-2099.

`fixed` is the set of remediation ids already carried out: the next "collection" no longer contains that
permission or finding, which is how the demo closes the loop from ticket to a new snapshot.
"""
import random

MATURITY = ["none", "poc", "functional", "weaponized"]
ROLES = ["web", "api", "worker", "batch", "cache", "queue", "admin", "etl"]
OWNERS = ["payments-team", "platform-team", "data-team", "growth-team", "identity-team", "logistics-team"]


def remediation_id(kind, *parts):
    return "|".join([kind, *parts])


def build(scale=1.0, seed=11, fixed=frozenset()):
    """-> ({"aws": .., "azure": .., "entra": ..}, expected) where expected lists the seeded attack chains by node name."""
    rng = random.Random(seed)
    aws = {"account": "111122223333", "ec2": [], "iam_roles": [], "secrets": [], "datastores": [], "inspector_findings": []}
    az = {"subscription": "sub-7f3a", "virtualMachines": [], "keyVaultSecrets": [], "sqlDatabases": [], "defenderFindings": [], "roleAssignments": []}
    entra = {"tenantId": "t-contoso-synthetic", "users": [], "groups": [], "servicePrincipals": [], "federations": []}
    cve_n = [0]

    def finding(resource, provider, cvss=None, kev=None, maturity=None):
        cve_n[0] += 1
        f = {"cve": f"CVE-2099-{cve_n[0]:05d}", "cvss": cvss if cvss is not None else round(min(10, max(2, rng.betavariate(5, 2) * 10)), 1),
             "kev": rng.random() < 0.04 if kev is None else kev, "maturity": maturity or rng.choices(MATURITY, [55, 25, 14, 6])[0]}
        if remediation_id("patch", resource, f["cve"]) in fixed:
            return None
        if provider == "aws":
            aws["inspector_findings"].append({"resource": resource, "cve": f["cve"], "cvss": f["cvss"], "kev": f["kev"], "exploit_maturity": f["maturity"]})
        else:
            az["defenderFindings"].append({"resourceId": resource, "cve": f["cve"], "cvss": f["cvss"], "kev": f["kev"], "exploitMaturity": f["maturity"]})
        return f["cve"]

    def allow(role, action, resource):
        if remediation_id("revoke", role["Arn"], action, resource) not in fixed:
            role["Allows"].append({"Action": action, "Resource": resource})

    # ---- background: apps that mostly keep to themselves ------------------------------------------------
    n_apps = max(12, int(600 * scale))
    for a in range(n_apps):
        app, owner, on_aws = f"app{a:03d}", rng.choice(OWNERS), rng.random() < 0.6
        critical = a < max(3, int(14 * scale))          # these own a crown-jewel datastore and are locked down
        n_w = rng.randint(8, 12)
        if on_aws:
            role = {"Arn": f"arn:aws:iam::111122223333:role/{app}-runtime", "Name": f"{app}-runtime", "TrustedPrincipals": [], "Allows": []}
            aws["iam_roles"].append(role)
            ci = {"Arn": f"arn:aws:iam::111122223333:role/{app}-deploy", "Name": f"{app}-deploy", "TrustedPrincipals": [], "Allows": []}
            aws["iam_roles"].append(ci)
            stores = []
            for d in range(rng.randint(2, 3)):
                arn = f"arn:aws:rds:us-east-1:111122223333:db:{app}-db{d}"
                aws["datastores"].append({"Arn": arn, "Name": f"{app}-db{d}", "Engine": rng.choice(["postgres", "mysql", "s3"]),
                                          "Tags": {"criticality": 5 if (critical and d == 0) else rng.randint(1, 4), "owner": owner, "app": app}})
                stores.append(arn)
            for s in range(2):
                sarn = f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{app}/db{s}"
                aws["secrets"].append({"Arn": sarn, "Name": f"{app}/db{s}", "Unlocks": stores[s % len(stores)], "Tags": {"owner": owner}})
                allow(ci if critical else role, "secretsmanager:GetSecretValue", sarn)      # critical apps: only the deploy role reads secrets
            if not critical:
                allow(role, "rds-db:connect", stores[-1])
            ids = [f"i-{a:03d}{w:02d}" for w in range(n_w)]
            for w, iid in enumerate(ids):
                public = (not critical) and rng.random() < 0.05
                aws["ec2"].append({"InstanceId": iid, "Name": f"{app}-{ROLES[w % 8]}-{w}", "PublicIp": public, "OpenPorts": [443] if public else [],
                                   "IamInstanceProfile": role["Arn"], "Tags": {"app": app, "env": "prod", "owner": owner, "asg": f"{app}-{ROLES[w % 8]}"},
                                   "Reaches": rng.sample(ids, 2) + ([f"i-{rng.randrange(n_apps):03d}00"] if rng.random() < 0.03 else [])})
                for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
                    finding(iid, "aws")
        else:
            sp = {"id": f"sp-{app}", "displayName": f"{app}-identity"}
            entra["servicePrincipals"].append(sp)
            stores = []
            for d in range(rng.randint(2, 3)):
                did = f"/subscriptions/sub-7f3a/sql/{app}-sql{d}"
                az["sqlDatabases"].append({"id": did, "name": f"{app}-sql{d}", "tags": {"criticality": 5 if (critical and d == 0) else rng.randint(1, 4), "owner": owner, "app": app}})
                stores.append(did)
            for s in range(2):
                kid = f"/subscriptions/sub-7f3a/vaults/{app}-kv/secrets/s{s}"
                if not critical:
                    az["keyVaultSecrets"].append({"id": kid, "name": f"{app}-kv/s{s}", "accessPolicies": [sp["id"]], "unlocks": stores[s % len(stores)], "tags": {"owner": owner}})
                else:
                    az["keyVaultSecrets"].append({"id": kid, "name": f"{app}-kv/s{s}", "accessPolicies": [], "unlocks": stores[s % len(stores)], "tags": {"owner": owner}})
            ids = [f"/subscriptions/sub-7f3a/vm/{app}-vm{w}" for w in range(n_w)]
            for w, vid in enumerate(ids):
                public = (not critical) and rng.random() < 0.05
                az["virtualMachines"].append({"id": vid, "name": f"{app}-{ROLES[w % 8]}-{w}", "publicIp": public, "managedIdentity": sp["id"],
                                              "tags": {"app": app, "env": "prod", "owner": owner, "scaleSet": f"{app}-{ROLES[w % 8]}"}, "reaches": rng.sample(ids, 2)})
                for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
                    finding(vid, "azure")

    # ---- people ------------------------------------------------------------------------------------------
    n_users = int(3000 * scale)
    for u in range(n_users):
        entra["users"].append({"id": f"u-{u:05d}", "userPrincipalName": f"user{u:05d}@synthetic.example", "mfa": rng.random() < 0.93, "privileged": rng.random() < 0.02})
    for g in range(max(4, int(500 * scale))):
        entra["groups"].append({"id": f"g-{g:04d}", "displayName": f"team-{g:04d}", "members": [f"u-{rng.randrange(n_users):05d}" for _ in range(rng.randint(3, 12))]})
    for g in rng.sample(entra["groups"], max(2, int(40 * scale))):      # some teams can sign in to a non-critical app's deploy role
        role = rng.choice([r for r in aws["iam_roles"] if r["Name"].endswith("-deploy") and int(r["Name"][3:6]) >= 14 * scale])
        entra["federations"].append({"principalId": g["id"], "awsRoleArn": role["Arn"]})
        role["TrustedPrincipals"].append(g["id"])

    # ---- seeded chains: the purple-team scenarios with known answers -----------------------------------
    expected = []
    orders = "arn:aws:rds:us-east-1:111122223333:db:orders-db"
    aws["datastores"].append({"Arn": orders, "Name": "orders-db", "Engine": "postgres", "Tags": {"criticality": 5, "owner": "payments-team", "app": "orders"}})
    secret = "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db/orders-master"
    aws["secrets"].append({"Arn": secret, "Name": "prod/db/orders-master", "Unlocks": orders, "Tags": {"owner": "payments-team"}})
    web = {"Arn": "arn:aws:iam::111122223333:role/web-frontend-role", "Name": "web-frontend-role", "TrustedPrincipals": [], "Allows": []}
    deploy = {"Arn": "arn:aws:iam::111122223333:role/deploy-automation", "Name": "deploy-automation", "TrustedPrincipals": [], "Allows": []}
    batch = {"Arn": "arn:aws:iam::111122223333:role/batch-role", "Name": "batch-role", "TrustedPrincipals": [], "Allows": []}
    aws["iam_roles"] += [web, deploy, batch]
    allow(web, "sts:AssumeRole", deploy["Arn"])
    allow(deploy, "secretsmanager:GetSecretValue", secret)
    allow(batch, "rds-db:connect", orders)
    tags = {"app": "orders", "env": "prod", "owner": "payments-team"}
    aws["ec2"] += [
        {"InstanceId": "i-web-frontend", "Name": "web-frontend", "PublicIp": True, "OpenPorts": [443], "IamInstanceProfile": web["Arn"], "Tags": {**tags, "asg": "web-frontend"}, "Reaches": []},
        {"InstanceId": "i-api-gateway", "Name": "api-gateway", "PublicIp": True, "OpenPorts": [443, 8443], "IamInstanceProfile": None, "Tags": {**tags, "asg": "api-gateway"}, "Reaches": ["i-batch-worker"]},
        {"InstanceId": "i-batch-worker", "Name": "batch-worker", "PublicIp": False, "OpenPorts": [], "IamInstanceProfile": batch["Arn"], "Tags": {**tags, "asg": "batch-worker"}, "Reaches": []}]
    finding("i-web-frontend", "aws", 9.8, True, "weaponized")
    finding("i-api-gateway", "aws", 8.1, False, "functional")
    finding("i-batch-worker", "aws", 7.5, False, "functional")
    entra["servicePrincipals"].append({"id": "sp-jump-host", "displayName": "jump-host-identity"})
    az["virtualMachines"].append({"id": "/subscriptions/sub-7f3a/vm/jump-host", "name": "jump-host", "publicIp": True, "managedIdentity": "sp-jump-host",
                                  "tags": {"app": "ops", "env": "prod", "owner": "platform-team", "scaleSet": "jump-host"}, "reaches": []})
    finding("/subscriptions/sub-7f3a/vm/jump-host", "azure", 8.8, True, "functional")
    az["keyVaultSecrets"].append({"id": "/subscriptions/sub-7f3a/vaults/ops-kv/secrets/aws-deploy-key", "name": "ops-kv/aws-deploy-key",
                                  "accessPolicies": [] if remediation_id("revoke", "sp-jump-host", "kv:get", "/subscriptions/sub-7f3a/vaults/ops-kv/secrets/aws-deploy-key") in fixed else ["sp-jump-host"],
                                  "unlocks": deploy["Arn"], "tags": {"owner": "platform-team"}})
    expected += [
        {"name": "A: public web tier to the orders database", "target": "orders-db",
         "nodes": ["Internet", "web-frontend", "web-frontend-role", "deploy-automation", "prod/db/orders-master", "orders-db"]},
        {"name": "B: API gateway, lateral move, direct database access", "target": "orders-db", "nodes": ["Internet", "api-gateway", "batch-worker", "batch-role", "orders-db"]},
        {"name": "C: Azure jump host to an AWS key in a vault", "target": "orders-db",
         "nodes": ["Internet", "jump-host", "jump-host-identity", "ops-kv/aws-deploy-key", "deploy-automation", "prod/db/orders-master", "orders-db"]}]
    # more scenarios: a public, exploitable workload wired to a locked-down app's crown jewel, by a varying route
    jewels = [d for d in aws["datastores"] if d["Tags"]["criticality"] == 5 and d["Name"] != "orders-db"]
    for k, d in enumerate(jewels[:max(2, int(8 * scale))]):
        app = d["Tags"]["app"]
        role = {"Arn": f"arn:aws:iam::111122223333:role/{app}-legacy-{k}", "Name": f"{app}-legacy-{k}", "TrustedPrincipals": [], "Allows": []}
        aws["iam_roles"].append(role)
        iid, name = f"i-legacy-{k}", f"{app}-legacy-portal"
        aws["ec2"].append({"InstanceId": iid, "Name": name, "PublicIp": True, "OpenPorts": [443], "IamInstanceProfile": role["Arn"],
                           "Tags": {"app": app, "env": "prod", "owner": d["Tags"]["owner"], "asg": name}, "Reaches": []})
        finding(iid, "aws", round(rng.uniform(6.5, 8.9), 1), rng.random() < 0.4, rng.choice(["functional", "weaponized", "poc"]))
        if k % 2:
            sarn = f"arn:aws:secretsmanager:us-east-1:111122223333:secret:{app}/db0"
            allow(role, "secretsmanager:GetSecretValue", sarn)
            nodes = ["Internet", name, role["Name"], f"{app}/db0", d["Name"]]
        else:
            allow(role, "rds-db:connect", d["Arn"])
            nodes = ["Internet", name, role["Name"], d["Name"]]
        expected.append({"name": f"legacy portal into {app}", "target": d["Name"], "nodes": nodes})
    # a privileged person without MFA who can sign in to the deploy role
    entra["users"].append({"id": "u-admin-nomfa", "userPrincipalName": "ops.admin@synthetic.example", "mfa": False, "privileged": True})
    entra["groups"].append({"id": "g-cloud-admins", "displayName": "cloud-admins", "members": ["u-admin-nomfa"]})
    if remediation_id("revoke", "g-cloud-admins", "federation", deploy["Arn"]) not in fixed:
        entra["federations"].append({"principalId": "g-cloud-admins", "awsRoleArn": deploy["Arn"]})
        deploy["TrustedPrincipals"].append("g-cloud-admins")
    expected.append({"name": "D: admin without MFA, federated into the deploy role", "target": "orders-db",
                     "nodes": ["Internet", "ops.admin@synthetic.example", "cloud-admins", "deploy-automation", "prod/db/orders-master", "orders-db"]})
    # fixes that are not handled where the object is created
    for kv in az["keyVaultSecrets"]:
        kv["accessPolicies"] = [x for x in kv["accessPolicies"] if remediation_id("revoke", x, "kv:get", kv["id"]) not in fixed]
    entra["federations"] = [f for f in entra["federations"] if remediation_id("revoke", f["principalId"], "federation", f["awsRoleArn"]) not in fixed]
    for u in entra["users"]:
        u["mfa"] = u["mfa"] or remediation_id("mfa", u["id"]) in fixed
    return {"aws": aws, "azure": az, "entra": entra}, expected
