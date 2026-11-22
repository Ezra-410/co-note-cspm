# Milestone 3 — Cloud Custodian policy enforcement

**Tool:** Cloud Custodian (c7n) 0.9.53 in `cloud-custodian/custodian-env/` (pinned in `requirements-custodian.txt`)
**Policies:** `cloud-custodian/policies/` · **Change log:** `registers/remediation_log.csv` · **Runbook:** `docs/RUNBOOK-REMEDIATION.md`

## 1. Installation and authentication

| Item | Value |
|---|---|
| Install | `python3 -m venv custodian-env` → `pip install -r requirements-custodian.txt` → `custodian version` = 0.9.53 |
| Detection identity | `conote-security-audit` (profile `conote-audit`): read-only, may write metrics to `CloudMaid` / `CoNote/CSPM` only |
| Remediation identity | role `conote-cspm-remediator` (profile `conote-remediator`): **MFA required**; can only revoke SG ingress on `Project=co-note` groups and restore the S3 public block on `conote-*` buckets |
| Multi-cloud packages | `c7n-azure`, `c7n-gcp` (Milestone 7, `requirements-custodian-multicloud.txt`) |

Detection and correction use **different identities**: a detection run cannot change anything, even by mistake.

## 2. Policies (Compliance as Code)

| File | Policies | Type |
|---|---|---|
| `security-baseline.yml` | `detect-public-ssh-access`, `detect-public-s3-access-block-disabled`, `detect-public-admin-ports` (3389/3306/5432/2375/2376), `detect-s3-public-policy` | detection |
| `aws/public-exposure.yml` | admin ports to internet, S3 block incomplete, public IP not declared public, default SG with rules | detection |
| `aws/encryption.yml` | S3 without default encryption, unencrypted EBS, S3 versioning off | detection |
| `aws/identity.yml` | IAM user without MFA, access keys > 90 days, user with AdministratorAccess, CloudTrail not multi-region, missing Owner tag | detection |
| `remediate-public-ssh.yml` | `remediate-public-ssh-access`: `remove-permissions: matched`, scoped to `tag:Project = co-note` | **remediation** |
| `remediate-s3-public-access.yml` | restore 4/4 public block; remove the `PublicShareDrift` policy statement | **remediation** (final challenge) |

Every policy carries its NIST SP 800-53 / CIS reference in `description`.

**Note on the lab's syntax:** `Cidr: "0.0.0.0/0"` validates, but the explicit form `Cidr: {value: "0.0.0.0/0"}` is used, plus an IPv6 `::/0` branch. `custodian validate policies/aws/` fails because validate needs files: use `policies/aws/*.yml`.

## 3. Validation and baseline (dry run)

`custodian validate …` → **Configuration valid** for all files.

Baseline dry run, 2026-11-19 07:56 UTC, auditor (`output-attempt1/01-baseline`):

| Policy | Matches | Interpretation |
|---|---|---|
| detect-public-ssh-access / admin ports / S3 block / S3 public policy | 0 | no exposure at baseline |
| aws-default-sg-has-rules | **1** | default VPC's default SG allows traffic (= M1 risk R3, confirmed by a 2nd tool) |
| aws-iam-user-with-admin-policy | **1** | `Ezra` (= Prowler F-01: two tools agree) |
| aws-iam-user-without-mfa | **1** | `conote-security-audit`: **false positive in context**, the user has no console password, so MFA does not apply; documented, not "fixed" |
| all others (encryption, versioning, EBS, CloudTrail, tags, key age) | 0 | compliant |

## 4. Demonstration: detect → approve → remediate → verify

| Time (UTC) | Step | Evidence |
|---|---|---|
| 08:28:24 | **Drift**: `Ezra` opens 22/tcp to 0.0.0.0/0 on `conote-admin-sg` (rule `sgr-07a1f04de2b9ccbed`, "temporary debug") with `scripts/simulate-drift.sh ssh` | script output, describe table |
| ~08:29 | **Real-time alert**: EventBridge → SNS email "RISKY CHANGE AuthorizeSecurityGroupIngress … by user/Ezra" | email screenshot |
| 08:33:48 | **Detection** (auditor): `detect-public-ssh-access` count **1** | `output/02-detect/`, `before-sg.json` |
| 08:34:29 | **Dry run** with remediator: would affect `sg-09824c64adf8aaacb` only | `output/03-remediate-dryrun/` (count 1) |
| 08:34 | **Approval** recorded (CHG-001), 5 pre-checks: 1 group affected · no workflow depends on SSH (admin = SSM) · alternative = SSM Session Manager · tested in lab account · owner approval | `registers/remediation_log.csv` |
| 08:34:48 | First execution **refused**: invalid MFA code → AssumeRole AccessDenied (the MFA gate works) | `04-remediate/custodian-run.log` |
| 08:35:38 | **Remediation**: `action:removepermissions resources:1` | `output/04-remediate/` |
| 08:35 | **After** (AWS CLI): `IpPermissions = []` | `after-sg.json` |
| 08:41 | **Verification** (auditor, no cache): `detect-public-ssh-access` count **0** | `output/05-verify/` |
| — | **CloudTrail**: `AuthorizeSecurityGroupIngress` (Ezra) → `RevokeSecurityGroupIngress` (remediator session) | lookup-events screenshot |

**Before:**
```json
[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"Description":"temporary debug - drift test","CidrIp":"0.0.0.0/0"}]}]
```
**After:** `[]`

Only the matched rule was removed (`ingress: matched`). The group, its attachment to the instance, and every other rule were untouched.

## 5. Execution logs and metrics

- Per policy: `output/<run>/<policy>/custodian-run.log` (count, duration, actions), `resources.json` (matched resources), `metadata.json`.
- `custodian run -m aws` publishes to CloudWatch namespace **`CloudMaid`** per policy (`ResourceCount`, `ResourceTime`, `ActionTime`). This is the basis of the alarms in Milestone 6.

## 6. Problems met and lessons learned

| # | What happened | Why it matters | Fix |
|---|---|---|---|
| L1 | First attempt: drift script printed its first line, but `conote-admin` had **no region**, so the change was never made. Detection "passed" with 0, and the remediation log was wrongly marked success. | A "0 findings" result is meaningless if the bad state was never created. **Verify the precondition**, and never record success without evidence. | region set; false log line removed; demo redone |
| L2 | Verification right after the fix still showed **count 1** (`time:0.00`). | Custodian **caches API results for 15 minutes** by default. The verify run re-used the pre-fix picture; the AWS CLI showed the truth. A 15-min scheduled check could report stale state. | `--cache-period 0` for verification and in `custodian-scan.sh` / `exposure-check.sh` |
| L3 | First remediation attempt rejected (invalid MFA code). | The human approval gate works as designed. | retried with a fresh code |

---

## 7. Investigation questions

**1. Detecting vs enforcing?**
**Detecting** is the smoke alarm: it rings when there's a problem. **Enforcing** is the sprinkler: it does something about it (`remove-permissions`). Our baseline policies only detect; `remediate-*.yml` enforce, and only after approval.

**2. What is Compliance as Code?**
Writing the security rules as files (`security-baseline.yml`) instead of in a Word document. A computer can then check them on every resource, every time. Like code, they're versioned in Git, reviewed and tested.

**3. Why YAML?**
It's readable by both humans and machines: a security officer can understand `Ports: [22]` and `Cidr: 0.0.0.0/0` without being a programmer. It's also easy to diff in Git and to validate against a schema (`custodian validate`).

**4. Scheduled vs event-driven policy?**
**Scheduled** = a guard who walks around every hour (our cron / GitHub Actions). **Event-driven** = a motion sensor that reacts the second a door opens: CloudTrail event → Lambda or EventBridge (our risky-change rule). Scheduled catches everything eventually; event-driven catches changes fast.

**5. Why dry-run first?**
To see **exactly what would change** before changing it. Our dry run showed one group, the expected one. If it had listed 50 groups, the filter would have been wrong, and we'd have found out without breaking anything.

**6. What if auto-remediation disables something production needs?**
An **outage caused by the security tool**: the application stops, customers are affected, and people lose trust in security automation. Example: if Co-note's admins really used SSH, our fix would lock them out. That's why we checked that SSM access exists first.

**7. Should every violation be auto-corrected?**
No. Auto-fix only what is **clearly bad, low-risk to undo, and well understood**, like an SSH rule open to the whole internet in a test account. Everything else is detect + alert + human decision. Some findings are even accepted on purpose (our exceptions register).

**8. Who authorises changes to production?**
The **resource owner** (here: Ezra as infrastructure owner), through a recorded change (CHG-001), with security advising. The tool can execute, but it doesn't decide.

**9. How to version-control and review policies?**
Keep them in Git (`co-note-cspm` repo), change them through **pull requests** reviewed by another person, run `custodian validate` in CI, and tag releases. It's the same pipeline discipline as Lab 02.

**10. What if a resource becomes non-compliant right after a scan?**
It stays exposed until the next scan, up to 1 hour with the hourly scan or 15 minutes with the exposure check. That gap is why we added the **EventBridge real-time alert**: the email arrived about a minute after the SSH rule was opened.

**11. How to detect a resource that keeps becoming non-compliant?**
- Count recurrences: the `recurrence_count` column in the findings register, and Custodian metrics over time.
- Look in CloudTrail for **who** keeps re-creating the rule, then fix the **cause**: a person, a script, or a Terraform file that differs from reality.

**12. Preventive vs corrective governance?**
**Preventive** stops the bad change from happening at all: a CI scan of Terraform in Lab 02, SCPs, IAM permissions that forbid it, the S3 account-level block. **Corrective** finds it after it happened and fixes it: Custodian remediation. You need both, because prevention never catches everything (our SSH change bypassed the pipeline).
