# Milestone 5 — Powerpipe CSPM dashboard

**Tools:** Powerpipe v1.8.0 · Steampipe v2.5.1 (service on port 9193) · mod `github.com/turbot/steampipe-mod-aws-compliance@v1.14.0`
**Dashboard code:** `dashboard/mod.pp`, `dashboard/conote_cspm.pp` (mod `conote_cspm`) · **Served at:** `powerpipe server` → http://localhost:9033
**Benchmark exports:** `reports/m5/cis_v500*.html|csv` (not committed)

## 1. Architecture

```
AWS APIs ──(read-only conote-audit)──► Steampipe AWS plugin ─┐
data/*.csv  (Prowler results, scan & exposure history) ─────┼─► Steampipe (PostgreSQL :9193) ──► Powerpipe ──► browser :9033
registers/*.csv (findings, remediation log, exceptions) ────┘        CSV plugin
```

- **Live** panels query AWS at page load (sections B and E), so they always show the current configuration.
- **Assessment** panels read the latest Prowler results and the registers (A, C, D).
- The dashboard is a **view**, not the source of truth: raw reports stay in `reports/`, decisions in `registers/`.

## 2. Dashboard content (lab sections A–E)

| Section | Panels | Source | Value on 2026-11-22 |
|---|---|---|---|
| Header | last Prowler scan, last exposure check (**red if stale**: > 26 h / > 1 h) | `csv.scan_history`, `csv.exposure_history` | Prowler 2026-11-19 03:51Z **(red: stale)** · exposure 2026-11-22 22:26Z |
| **A · Overview** | cloud resources · findings (FAIL) · critical · high · non-compliant resources · unintended public exposure; trend charts | AWS (live) + Prowler | **37 · 115 · 3 · 17 · 42 · 0 ✅** |
| **B · Public exposure** | public storage · SGs exposing admin ports · publicly accessible services (instance ⨝ public IP ⨝ open rule) · incomplete restrictions | AWS (live) | none · none · `conote-app-01` 3.248.188.9 on 80/443 (intended) · default SG `sg-0fede33b8a1f754fe` |
| **C · Compliance** | CIS pass rate · NIST 800-53 r5 pass rate · failed controls · manual checks; failed-controls table with CIS/NIST mapping | Prowler | **CIS 57.3 % · NIST 68.3 % · 84 failed checks · 6 manual** |
| **D · Remediation** | awaiting · being remediated · resolved · accepted · recurring · remediation rate; findings register table | `registers/findings_register.csv` | 14 · 1 · **1 (F-SSH-01)** · 10 · 0 · 6.3 % |
| **E · Inventory** | resources by service / region / environment; resources without required tags | AWS (live) | ec2 13, s3 4, cloudwatch 3… · eu-west-1 · `lab` · default SG untagged |

**Metric definitions** (displayed on the dashboard, not invented scores):
- *Pass rate* = PASS ÷ (PASS + FAIL) of the Prowler checks mapped to the framework; MANUAL excluded. Internal metric; the official per-control result is the Powerpipe benchmark.
- *Remediation rate* = resolved ÷ (all findings − accepted).
- *Unintended public exposure* = buckets with a public policy or incomplete block + SGs with admin ports open to the internet + instances with a public IP **not tagged** `Exposure=public-intended`.

## 3. Built-in compliance benchmark: CIS AWS Foundations 5.0

| Run | When (UTC) | OK | ALARM | SKIP | INFO | ERROR | Total rows |
|---|---|---|---|---|---|---|---|
| 1 | 2026-11-22 22:40 | 53 | 56 | 67 | 4 | **6** | 186 |
| 2 (after credential report) | 2026-11-22 22:49 | **61** | 57 | 68 | 5 | **2** | 193 |

**The 6 errors of run 1 were "not checked", not "compliant":**
- **4 controls** (1.6, 1.9, 1.10, 1.11) read the IAM **credential report**, which AWS only produces on request. `aws iam generate-credential-report` (as the auditor) fixed them: they were evaluated in run 2.
- **2 controls** (2.1.3 Macie, 4.16 Security Hub) return `SubscriptionRequiredException`: the **services are not enabled**. This is a real failing control, recorded as finding F-28 (cost decision).

**56 alarms ≈ 30 root causes:**

| Root cause | CIS controls | Alarms | Register |
|---|---|---|---|
| No CloudTrail → CloudWatch metric-filter alarms | 4.1 – 4.15 | 15 | F-17 |
| IAM Access Analyzer off | 1.19 (one per region) | 17 | F-19 |
| S3 MFA delete | 2.1.2 | 4 | F-22 (accepted) |
| **S3 object-level logging (CloudTrail data events) off** | 3.8, 3.9 | 8 | **F-27 (new)** |
| **Default VPC without flow logs** | 3.7 | 1 | **F-29 (new)** |
| Default SG of default VPC allows traffic | 5.5 | 1 | M1 R3 |
| Default NACLs allow admin ports | 5.2 | 2 | F-08 |
| Password policy · users not in groups · security contact · **no AWS Support role** · root hardware MFA | 1.7, 1.8, 1.14, 1.2, **1.16**, 1.5 | 7 | F-16, F-20, F-21, **F-30 (new)**, F-03 |
| AWS Config off | 3.3 | 1 | F-18 |

## 4. Prowler vs Powerpipe on CIS 5.0

| | Prowler (compliance run) | Powerpipe benchmark (run 2) |
|---|---|---|
| Counts | per finding | per control × resource (one row per region for regional controls) |
| Automatic pass rate | 53.2 % (findings) · 57.3 % (full scan, CIS-mapped checks) | 61 ÷ (61 + 57) = **51.7 %** |
| Manual / not decidable | MANUAL status | SKIP (68) |
| Unique to the tool | IAM admin on user, long-lived keys, Bedrock/SageMaker (N/A) | S3 data-event logging, default-VPC flow logs, AWS Support role |

**Conclusion:** the two tools agree on the important failures, but their **percentages are not comparable**. Each counts differently, and a percentage without its definition is meaningless. Using both raised **3 extra findings**. The **default VPC** was flagged independently by **four** tools (CLI inventory, Custodian, Steampipe, Powerpipe): it is the clearest single recommendation of the lab.

## 5. Limitations
- Sections A/C show the **last** Prowler run (19 Nov). The red header card makes that visible. Scheduled scans (M6) keep it fresh.
- Live panels query only eu-west-1.
- The dashboard has no authentication: it listens on localhost only and must never be exposed on a network without an auth proxy.
- Pass rates measure automated checks only. 68 skipped/manual controls need a human.

---

## 6. Remediation tracking format

`registers/findings_register.csv` (one row per decision, read by section D):
`finding_id, detected_at, source_tool, check_id, resource, severity, requirement, risk, owner, status (open | in_progress | resolved | accepted), remediation, priority (P1–P3 | Accepted), resolved_at, recurrence_count, evidence`

Each resolved finding links to a change in `registers/remediation_log.csv` (approval, dry-run evidence, result, verification). Each accepted one links to `registers/exceptions.csv` (reason, compensating control, approver, expiry).

## 7. Investigation questions

**1. Security report vs security dashboard?**
A **report** is a photo: a full picture of one moment, for reading and archiving (Prowler HTML, benchmark export). A **dashboard** is a live window: always open, refreshed from current data, showing the few numbers that matter and how they change.

**2. Metrics for a security engineer?**
Details to act on:
- open findings by severity, **with resource names**
- public exposure (which group, which port)
- failed controls
- items awaiting remediation
- recurring violations
- data age

Sections B, C (table) and D of our dashboard.

**3. Metrics for a CTO or infrastructure manager?**
Few, trend-based numbers:
- critical/high count and **its trend**
- unintended public exposure (yes/no)
- compliance pass rates
- remediation rate and accepted risks with expiry dates
- resources by environment

Section A, the C cards and the D cards.

**4. Why separate critical, high, medium and low?**
Because 115 findings in one number tells you nothing about urgency. **3 criticals** that give full account control matter more than 38 lows about log retention. Severity decides **what gets fixed first** and what wakes someone up at night.

**5. What happens when a dashboard shows old scan results?**
People trust a picture that may no longer be true: a fixed problem still looks open, or worse, a new one is invisible. That's why our "Last Prowler scan" card turned **red** after 26 hours (scan of 19 Nov).

**6. How to avoid presenting an incomplete inventory as a healthy posture?**
Show **what was covered** next to the result:
- regions scanned
- identity and permissions used
- errors and skipped checks
- resources outside the IaC tag scope

Our tagging inventory missed the AWS-created **default VPC**. Only the live per-table queries found it. "0 findings" over half the account is not "secure".

**7. Should a resource that cannot be assessed be called compliant?**
**No.** It's **unknown**. Our benchmark's 6 ERRORs (credential report missing, Macie and Security Hub disabled) were not passes. After generating the credential report, 4 of them became real results.

**8. How does the dashboard show a finding was really remediated?**
Three pieces of evidence that agree:
1. The **live** panel no longer shows it (B: no admin port open).
2. The **register** has status *resolved* with date and evidence (F-SSH-01 → CHG-001).
3. A **re-scan** confirms it.

The register alone is a claim; the live query is the proof.

**9. How to compare two cloud accounts?**
- Use **the same benchmark version** (CIS 5.0 for both).
- Use **the same tool**, same regions and same scan date.
- Compare **severity counts per resource** and exposure, not only percentages, because a bigger account has more findings.
- Normalise: findings per 100 resources.

**10. What should be available for an audit?**
- Dated raw reports (Prowler OCSF/HTML, benchmark exports)
- The inventory
- The findings register with owners
- Exceptions with approvals and expiry dates
- The remediation log with before/after evidence
- CloudTrail records of each change
- Policy and dashboard code in Git, with history
