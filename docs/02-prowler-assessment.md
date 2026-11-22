# Milestone 2 — Prowler security assessment

**Tool:** Prowler 5.50.0 (virtual environment `prowler-env/`, pinned in `requirements-prowler.txt`)
**Identity:** `conote-security-audit` (SecurityAudit + ViewOnlyAccess + read additions, read-only)
**Scope:** account 093397426920, region eu-west-1 + global services (IAM, S3 account settings)
**Register:** `registers/findings_register.csv` · **Exceptions:** `registers/exceptions.csv`

## 1. Installation and access

| Step | Evidence |
|---|---|
| Install | `python3 -m venv prowler-env` → `pip install -r requirements-prowler.txt` → `Prowler 5.50.0` |
| Authentication | `AWS_PROFILE=conote-audit` → `sts get-caller-identity` = `user/conote-security-audit` |
| Supported frameworks | `prowler aws --list-compliance` → chose **`cis_5.0_aws`** (newest CIS in this version; the lab's example `cis_2.0_aws` is outdated) and **`nist_800_53_revision_5_aws`** |
| Automation | `scripts/prowler-scan.sh` (full scan) and `scripts/compliance-scan.sh` (CIS + NIST) |

## 2. Assessments executed

| Run | Started (UTC) | Command | Checked | FAIL | PASS | MANUAL |
|---|---|---|---|---|---|---|
| Full assessment | 2026-11-19 03:51 | `scripts/prowler-scan.sh` | 341 results | **115** | 220 | 6 |
| Compliance (CIS 5.0 + NIST r5) | 2026-11-19 04:07 | `scripts/compliance-scan.sh` | 146 results | 54 | 88 | 4 |

**Full assessment, FAIL by severity:** Critical **3** · High **17** · Medium **57** · Low **38**

**Reports generated** (`reports/prowler/<date>/`, not committed):
- `prowler-output-…​.ocsf.json`: machine-readable (OCSF standard), feeds the dashboard and metrics
- `….html`: human report · `….csv`: spreadsheet
- `compliance/`: one CSV per framework (CIS 1.4 → 7.0, NIST, ISO 27001, …)

## 3. Compliance results

| Framework | FAIL | PASS | Pass rate | Weakest sections |
|---|---|---|---|---|
| **CIS AWS Foundations 5.0** | 44 | 50 | **53.2 %** | 4 Monitoring (15 FAIL), 1 IAM (15 FAIL) |
| **NIST SP 800-53 rev 5** | 29 | 71 | **71.0 %** | AC (access control), AU (audit) |

CIS 5.0 by section: 1 IAM: L1 FAIL 13, L2 FAIL 2 · 2 Storage: L1 FAIL 1, L2 FAIL 4 · 3 Logging: L1 PASS, L2 FAIL 3 · 4 Monitoring: L1 FAIL 9, L2 FAIL 6 · 5 Networking: L1 FAIL 6.

> These percentages are Prowler's **finding** pass rates, not a certification score. Over half of the CIS failures come from **one missing capability**: CloudTrail is not sent to CloudWatch Logs with metric-filter alarms (CIS 4.x). One fix (F-17) closes 14 checks.

## 4. Findings by service (compliance run, CIS 5.0 + NIST checks)

| Service | FAIL | What dominates |
|---|---|---|
| CloudWatch | 17 | CIS 4.x monitoring alarms missing (one cause) |
| IAM | 18 | administrator on a user, long-lived keys, password policy, root used at set-up |
| EC2 / VPC | 7 + design | default NACLs, account IMDSv2 default, public instance with a role, single AZ |
| S3 | 6 | account-level public block (intentional for the lab), KMS vs SSE-S3, MFA delete |
| SNS, Config, Organizations | 1 each | encryption of alerts; no Config recorder; no Organization |
| Bedrock / SageMaker | 8 | **not applicable**: services not used (noise to mute) |

## 5. Critical findings

| # | Finding | Resource | Decision |
|---|---|---|---|
| F-01 | IAM user has AdministratorAccess | `Ezra` | **Fix (P1)**: admin via MFA-protected role |
| F-02 | A `*:*` administrator policy is in use | AdministratorAccess | Closed with F-01 |
| F-03 | Root has no **hardware** MFA | root | **Accepted** (EXC-L03): virtual MFA, no root keys, root unused |

**No critical public exposure was found:** no open SSH/RDP, no public bucket. The criticals are all about **who holds power** (identity), which is also the most common real-world cloud breach path.

## 6. Remediation priorities

| Priority | Rule | Findings |
|---|---|---|
| **P1: now** | Critical/High with a realistic attack path | F-01/F-02 admin user, F-04 long-lived keys (already leaked twice) |
| **P2: quick wins** (free, < 15 min each) | Low effort, closes many checks | F-07 account IMDSv2 default, F-16 password policy (7 checks), F-17 CIS 4.x alarms (14 checks), F-19 Access Analyzer, F-21 security contact, F-11 confused-deputy condition, F-20 IAM group, F-06 root use (self-clears) |
| **P3: design** | Needs architecture work or cost | F-08 custom NACL, F-13 backups, F-18 AWS Config, F-23 log encryption/retention |
| **Accepted** | Documented exception, owner, expiry | F-03, F-05, F-09, F-10, F-12, F-14, F-15, F-22, F-24, F-25 |

How the list was ordered: **severity × exposure × exploitability × effort**. A *High* that is intended and compensated (open web port) ranks below a *Medium* that closes 14 checks with one change.

## 7. Limitations of this assessment
- Single region checked (eu-west-1 + global). Other regions are enabled but were not scanned.
- Results reflect the configuration at scan time only (point-in-time). Continuous checks come in Milestones 3 and 6.
- MANUAL checks (6) need a human: security contact, contact details, Nitro Enclave attestation, Trusted Advisor.
- Some checks are not applicable to a single Free-plan account (Organizations, FMS, premium support) and appear as FAIL. They must be muted with a justification, not ignored silently.

---

## 8. Investigation questions

**1. Security assessment vs vulnerability scan?**
A **vulnerability scan** looks for **bugs in software**, like an outdated nginx with a known CVE. A **security assessment** like Prowler looks at **how the cloud is configured**: is MFA on, is the bucket private, is logging enabled? Our server software may be perfectly patched while the account around it is wide open.

**2. What is a security finding?**
The result of one check against one resource: *"user Ezra: FAIL: has AdministratorAccess"*. It always has a check, a resource, a status (PASS/FAIL/MANUAL), a severity and a remediation.

**3. What is a compliance benchmark?**
A published checklist of good practices that experts agree on, like **CIS AWS Foundations** (hands-on settings) or **NIST SP 800-53** (control families). It's like a driving test: a fixed list of things you must do correctly.

**4. Does CIS-compliant mean secure?**
No. Passing the driving test doesn't mean you'll never crash. CIS checks known settings, but it can't judge your business logic, your application code, your data, or a clever attacker. Our account could reach 100 % CIS and still have a vulnerable web app on port 443.

**5. What happens when Prowler can't access a resource?**
The check can't decide. Depending on the check, it shows an error in the logs or no result for that resource. That means **"not assessed"**, never "compliant". That's why the auditor received Prowler's extra read permissions, and why "no finding" must be read carefully.

**6. Why can two executions give different results?**
- The cloud changed between the two runs (drift, new resources, a key got older).
- The **scope** was different: our compliance run checked 146 items instead of 341.
- A different Prowler version shipped new or changed checks.
- Different permissions or regions were used.
- Time-based checks like "root used in the last day" change on their own.

**7. Failed check vs check that couldn't run?**
**FAIL** = we looked, and the setting is wrong (a real problem). **Couldn't run** = we couldn't look (access denied, service unavailable): an **unknown**, possibly hiding a problem. Treat the unknown as a gap in your visibility and fix the access.

**8. How to prioritise hundreds of findings?**
1. Group them by **root cause**: our 14 CloudWatch findings are one fix.
2. Sort by **severity × exposure × exploitability**.
3. Do the **quick wins** first.
4. Accept with documentation what is intended or not applicable.

Prowler gave 115 FAILs; our register has 25 decisions.

**9. Can a finding be accepted temporarily?**
Yes, if it's written down with:
- a **reason**
- a **compensating control** (something else that reduces the risk)
- an **approver**
- an **expiry date**

Then it must be **reviewed** when it expires. Example: EXC-L01 (account-level S3 block off until the drift challenge is finished), expiring 2026-12-31.

**10. How to integrate Prowler into enterprise monitoring?**
- Run it **on a schedule**: daily (cron and GitHub Actions in our kit).
- Export **OCSF JSON** to a SIEM / Security Hub.
- Publish counts as **metrics with alarms**: our CloudWatch `CriticalFindings` alarm.
- Feed a **dashboard** (Milestone 5) and a **findings register** with owners and due dates.
- Re-scan to **verify** that each fix worked.
