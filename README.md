# Co-note CSPM — Cloud Security Posture Monitoring (CYB 319 · Lab 03)

Continuous security monitoring of the Co-note AWS environment, **after** deployment.
Lab 02 (repos `auto-monitor` / `auto-monitor-deployment`) secures what goes *into*
the cloud; this repo watches what the cloud *actually looks like* and catches drift.

| Tool | Responsibility in this project |
|---|---|
| **Prowler** | Security assessment + CIS 5.0 / NIST SP 800-53 r5 compliance findings |
| **Cloud Custodian** | Policy as Code: detection (hourly / 15 min) + controlled remediation |
| **Steampipe** | SQL over live AWS APIs: inventory, exposure, correlation |
| **Powerpipe** | CSPM dashboard (sections A–E) + AWS compliance benchmarks |
| **CloudWatch + EventBridge + SNS** | Alarms on scan metrics + real-time alerts on risky API calls |

## Layout

```
terraform/                 Co-note lab environment + CSPM identities + alerting
cloud-custodian/policies/  security-baseline.yml (detection), remediate-*.yml,
                           aws/ azure/ gcp/ (multi-cloud baseline)
steampipe/queries/         inventory, exposure, encryption/versioning, correlation
dashboard/                 Powerpipe mod: Co-note CSPM dashboard
scripts/                   prowler-scan, compliance-scan, custodian-scan,
                           exposure-check, drift simulation, cron schedule
registers/                 findings register, remediation log, exceptions (CSV)
.github/workflows/         scheduled cloud-side scans via OIDC (no AWS keys)
docs/                      milestone documentation, runbooks, decisions
```

## Identities (least privilege)

| Identity | Used by | Rights |
|---|---|---|
| `ezra-admin` (IAM user, MFA) | human admin, Terraform | administrator — never used by scanners |
| `conote-security-audit` (role) | Prowler, Steampipe, Custodian detection, cron | `SecurityAudit` + `ViewOnlyAccess` + small read additions; may only write CSPM metrics |
| `conote-cspm-remediator` (role) | Custodian remediation | revoke SG ingress / restore S3 public block on co-note resources only; **MFA required** |
| `conote-cspm-github` (role, OIDC) | scheduled GitHub Actions scans | same as audit role; only from `main` of this repo |

Reports, scan data and Terraform state are **never committed** (account and
resource identifiers) — see `.gitignore`.
