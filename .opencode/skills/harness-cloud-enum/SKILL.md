---
name: harness-cloud-enum
description: "Enumerate approved cloud assets and misconfigurations with read-only checks against the live account or collected evidence."
---

# Cloud — read-only, evidence first, live only with an approved identity

Source: `cloud-security-assessment`, `aws-enumeration` / `gcp-enumeration` / `azure-enumeration`, CIS Benchmarks (AWS/GCP/Azure), and the MTN `cloud.mtn.ci` evidence review (terraform state, bucket lists, provider bundles).

## Gate

The account / project / subscription and the read-only credential or evidence directory must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Read-only: no writes, no new resources, no privilege escalation attempts beyond a `--dry-run`, no key creation, no snapshot restore, no policy change.

Toolchain on this host (2026-11-13): **no provider CLI is installed** — `aws`, `gcloud`, `az`, `azcopy`, `kubectl`, `helm`, `docker`, `terraform`, `prowler`, `scoutsuite` are all absent; `trivy`, `nuclei` and `nmap` are present. So the default is **evidence-first (offline)**; a live probe only runs once the CLI is installed and the credential is in scope. A missing binary is recorded as a gap, never guessed or substituted. Do not install a provider CLI mid-engagement without an operator decision.

Cloud is not a five-step check. The checklist below is one branch per surface; use `cyber_tasks coverage profile=cloud` to seed it, then close each leaf only with the observation that proves it. A step you did not run stays `not-tested` with its reason.

## Steps

### 1. Scope, account and identity

Record which account/project/subscription is in scope, the exact credential used, and the identity it resolves to before any probe. One observation per fact. An "approximate" account, or a credential that turns out to be a personal one, stops the run.

### 2. Evidence inventory first (offline)

Read what is already collected before touching a live API: `terraform.tfstate` / `*.tf`, CloudFormation templates, `docker-compose.yml`, CI config, provider bundles already in `evidence/`, and any `cloud-<provider>.json` output. Record the source with `cyber_source` (chunk id) and build the entity graph (`cyber_entity`). Most misconfigurations (public bucket, open SG, over-broad role) are already visible here; a live read only confirms one.

```
cyber_process argv=["grep","-rnE","0\\.0\\.0\\.0/0|::/0|public-read|publicly_accessible|acl.*public","<evidence-dir>"]
cyber_process argv=["grep","-rnE","Action.*\\*|Resource.*\\*|assume_role|iam:PassRole","<evidence-dir>"]
```

### 3. IAM, roles and trust policies

The privilege-escalation graph, not a user list. Enumerate principals, attached/assumed policies, and **trust** relationships.

```
cyber_process argv=["aws","sts","get-caller-identity","--output","json"]
cyber_process argv=["aws","iam","get-account-authorization-details","--output","json"]
cyber_process argv=["aws","iam","list-roles","--output","json"]
```

GCP:

```
cyber_process argv=["gcloud","projects","get-iam-policy","<project>","--format=json"]
```

Azure:

```
cyber_process argv=["az","role","assignment","list","--all","--output","json"]
cyber_process argv=["az","ad","sp","list","--all","--output","json"]
```

Flag: `Action:"*"` + `Resource:"*"`, `iam:PassRole` + compute create, trust policy with foreign account or `*` principal, service account with `roles/owner`. Candidate until evidence + live read agree.

### 4. Storage

```
cyber_process argv=["aws","s3api","list-buckets","--output","json"]
cyber_process argv=["aws","s3api","get-bucket-acl","--bucket","<bucket>","--output","json"]
cyber_process argv=["aws","s3api","get-bucket-policy","--bucket","<bucket>","--output","json"]
cyber_process argv=["aws","s3api","get-public-access-block","--bucket","<bucket>","--output","json"]
```

GCP:

```
cyber_process argv=["gcloud","storage","buckets","describe","gs://<bucket>","--format=json"]
```

Azure:

```
cyber_process argv=["az","storage","account","list","--output","json"]
```

A 200 listing where the ACL says `public-read` is the signal; a `403` on a private bucket is the **negative control**. Never download objects — list metadata only.

### 5. Compute, images, containers and Kubernetes

Instances and images with public IPs, default/weak SSH, user-data or instance metadata containing secrets, unencrypted volumes, and shared AMIs/images. Kubernetes: anonymous API access, RBAC `cluster-admin` bound to a default SA, exposed dashboard, privileged/hostPath pods, `automountServiceAccountToken`, and a service account token reachable from a pod.

- AWS: `aws ec2 describe-instances`, `describe-images --owners self`, `aws eks list-clusters`
- GCP: `gcloud compute instances list`, `gcloud container clusters list`
- Azure: `az vm list -d`, `az aks list`
- Kubernetes (kubeconfig in scope): `kubectl auth can-i --list`, `kubectl get clusterrolebindings -o json`

### 6. Serverless and managed services

Functions and managed runtimes with over-broad execution roles, public function URLs, environment variables holding secrets, and event triggers that cross a trust boundary. Managed databases with `publicly_accessible=true` or `0.0.0.0/0` firewall. Message queues/topics with an anonymous or wildcard policy.

- AWS: `aws lambda list-functions`, `get-function-configuration`, `aws rds describe-db-instances`
- GCP: `gcloud functions list`, `gcloud sql instances list`
- Azure: `az functionapp list`, `az sql server list`

### 7. Network, security groups, firewalls and ingress

Ingress rules open to `0.0.0.0/0` or `::/0` on a sensitive port (22, 3389, 5432, 6379, 9200, 27017), default VPCs, missing flow logs, public load balancers over a private service, and a peering or VPN that reaches an out-of-scope network. One rule is a candidate; the finding is the rule plus the live service answering on it.

- AWS: `aws ec2 describe-security-groups`, `describe-vpcs`
- GCP: `gcloud compute firewall-rules list`, `gcloud compute networks list`
- Azure: `az network nsg list`, `az network nsg rule list`

### 8. DNS, certificates, load balancers and public exposure

Load balancers and API gateways pointing at an internal target, dangling DNS to an unclaimed host (subdomain takeover), certificates about to expire or with a wildcard `*`, and a public endpoint that fronts a private data store. Cross-check names with `harness-subdomain-enum` and `harness-ct-logs`; a name in CT does not authorise probing.

- AWS: `aws elbv2 describe-load-balancers`, `aws acm list-certificates`
- GCP: `gcloud compute forwarding-rules list`, `gcloud compute ssl-certificates list`
- Azure: `az network lb list`, `az network application-gateway list`

### 9. Secrets, KMS keys and secret references

Secrets Manager / Parameter Store / Key Vault / Secret Manager entries referenced in code or IaC, KMS keys with a wildcard key policy, keys scheduled for deletion still in use, and hardcoded credentials in user-data, function env, or CI variables. A reference is a candidate; the value is never printed — `harness-secret-scan` records the path and hash only, and the ledger keeps the value out.

- AWS: `aws secretsmanager list-secrets`, `aws kms list-keys`, `get-key-policy`
- GCP: `gcloud secrets list`, `gcloud kms keys list`
- Azure: `az keyvault list`, `az keyvault key list`

### 10. Logging, monitoring, audit trails and alerting

Whether the audit trail exists and covers the account (CloudTrail multi-region / Activity Log / Diagnostic Settings), whether logs are immutable (object-lock, separate account), whether GuardDuty / Security Command Center / Defender is on, and whether a high-severity alert has a destination. Absent or single-region audit logging is a finding on its own.

- AWS: `aws cloudtrail describe-trails`, `aws guardduty list-detectors`
- GCP: `gcloud logging sinks list`, `gcloud services list --enabled | grep security`
- Azure: `az monitor diagnostic-settings list`, `az security pricing list`

### 11. CI/CD, registries and infrastructure as code

Pipeline definitions with long-lived cloud keys in plaintext, OIDC trust allowing a broad repository/ref, self-hosted runners, and container registries open to push or with unscanned images. IaC with a hardcoded secret or a `0.0.0.0/0` rule. `trivy` (present) covers image and IaC config scanning: `trivy config <dir>`, `trivy image <ref>`.

### 12. Metadata endpoints and workload identity

Instance metadata reachable from the workload (`169.254.169.254`), IMDSv1 still enabled (SSRF → credential theft), a pod or function able to reach the metadata service, and a workload identity federated to a foreign principal. On a live host this is a single read of the metadata route through the workload, tied to the SSRF observation — never an unbounded crawl.

- AWS: IMDSv2 required (`aws ec2 describe-instances` → `HttpTokens: required`)
- GCP: `--metadata` / workload identity pool federated to an external IdP
- Azure: IMDS + managed identity assigned to the resource

### 13. Read-only negative controls and dry-run

No finding without a control. For each candidate record the control that shows the same call succeeding where it should and failing where it should not: a bucket that is genuinely private returns `403`, a policy that genuinely denies returns `AccessDenied`, an SG with a closed port refuses the connection. One `--dry-run` escalation check only when explicitly approved (`aws iam simulate-principal-policy`, `--dry-run`), never an assumed role beyond the test identity.

### 14. Triage and finding

Run `harness-vuln-triage` first. A cloud finding is `cyber_finding` with `evidence` = the observation ids (evidence file + live read + negative control), `sources` = the IaC/config chunk via `cyber_source`, and `checks` = reproduction / positive-control / negative-control. **No finding from a config file alone** — a quoted `public-read` string is not a public bucket until a read agrees. Map the finding to an OWASP category and a MITRE ATT&CK technique, and link the pivot in the entity graph (`cyber_entity relate`).

## Coverage checklist (seed with `cyber_tasks coverage profile=cloud`)

- [ ] scope, account and approved read-only identity
- [ ] evidence inventory and provider detection
- [ ] IAM principals, roles and trust policies
- [ ] storage buckets, containers and snapshots
- [ ] compute, images, containers and Kubernetes
- [ ] serverless functions and managed services
- [ ] network, security groups, firewalls and ingress
- [ ] DNS, certificates, load balancers and public exposure
- [ ] secrets, KMS keys and secret references
- [ ] logging, monitoring, audit trails and alerting
- [ ] CI/CD, registries and infrastructure as code
- [ ] metadata endpoints and workload identity
- [ ] read-only negative controls and dry-run validation
- [ ] evidence review and cleanup boundary

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| Bucket ACL `public-read` + anonymous list succeeds | 200 with object list | public bucket candidate |
| Bucket ACL `private` + anonymous list → 403 | AccessDenied | negative control confirmed |
| IAM policy `Action:*` + `Resource:*` on a principal | authorization-details JSON | over-permissive IAM candidate |
| Trust policy allows foreign account as principal | AssumeRolePolicyDocument | cross-account trust candidate |
| SG rule `0.0.0.0/0` on port 22 + nmap confirms SSH open | open port + SG JSON | public SSH candidate |
| SG rule `0.0.0.0/0` on port 22 but nmap shows filtered | no connection | SG exists but not reachable (verify) |
| IMDSv1 enabled on instance | HttpTokens: optional | SSRF → credential theft candidate |
| IMDSv2 required | HttpTokens: required | negative control confirmed |
| CloudTrail multi-region enabled | describe-trails JSON | negative control confirmed |
| No CloudTrail | empty or absent | missing audit trail candidate |
| Lambda env var contains secret | get-function-configuration | secret in env candidate |
| Kubernetes anonymous auth | `kubectl auth can-i --list` as anonymous | anon K8s access candidate |
| trivy config scan finds public SG in IaC | trivy output | IaC misconfiguration candidate |
| Private key in evidence directory | grep match | key exposure candidate |

A config file reference alone is not a finding. The finding requires a live read confirming the misconfiguration.

## Done

Evidence holds the read-only outputs and every misconfiguration candidate with its control. The account identity is recorded. No finding rests on a config file alone. A surface that was not tested (or a provider CLI that was missing) stays `not-tested` with its reason, and is reported as such rather than assumed covered.
