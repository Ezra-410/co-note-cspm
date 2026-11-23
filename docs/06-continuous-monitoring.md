# Milestone 6 — Continuous monitoring and security alerts

**Scripts:** `scripts/exposure-check.sh`, `custodian-scan.sh`, `prowler-scan.sh`, `compliance-scan.sh`, `crontab.txt`, `create-cloudmaid-alarm.sh`
**Cloud-side scheduler:** `.github/workflows/cspm-scheduled.yml` · **Alerting infrastructure:** `terraform/monitoring.tf` · **Test log:** `logs/m6-alert-test.log`

## 1. Monitoring schedule

| Assessment | Frequency | Laptop (cron) | Cloud (GitHub Actions, OIDC) | Output |
|---|---|---|---|---|
| Critical exposure checks | every 15 min | `*/15 * * * *` exposure-check.sh | `*/15 * * * *` | metric `PublicExposure`, `data/exposure_history.csv` |
| Cloud Custodian policies | hourly | `0 * * * *` custodian-scan.sh | — | `reports/custodian/<date>/`, metrics `CloudMaid` |
| Prowler assessment | daily 02:00 | `0 2 * * *` prowler-scan.sh | `0 2 * * *` | `reports/prowler/<date>/`, metrics `CriticalFindings` / `HighFindings` |
| Compliance (CIS 5.0 + NIST r5) | weekly, Sun 03:00 | `0 3 * * 0` compliance-scan.sh | — | `reports/prowler/<date>/compliance/` |
| Full posture review | monthly | — (human) | — | review of dashboard, register, exceptions |

These are lab settings, not universal requirements.

**Two schedulers on purpose:** cron runs only while WSL is up. The GitHub workflow runs in the cloud with a temporary OIDC role and no stored AWS key. If both stop, the `Scan-Missing` heartbeat alarm fires.

**Historical reports:** every run writes a new dated folder (e.g. `reports/prowler/2026-11-19_03-51-25` and `2026-11-23_11-51-27`) and appends to `data/scan_history.csv`. That allows comparisons such as 115 FAIL (19 Nov) → 80 FAIL + 33 MUTED (23 Nov).

## 2. Alerting architecture

```
                 ┌── every 15 min / hourly / daily ──────────────────────────────┐
 Custodian ─► violations ─► metrics (CoNote/CSPM, CloudMaid) ─► CloudWatch alarm ─┤
 Prowler   ─► findings   ─► CriticalFindings / HighFindings  ─► CloudWatch alarm ─┼─► SNS CoNote-CSPM-Alerts ─► email
 CloudTrail API call ─► EventBridge rule (SG opened, S3 block/policy/ACL changed) ┘   (real time, ~1 min)
```

| Alarm | Metric | Rule | State 23 Nov |
|---|---|---|---|
| CoNote-CSPM-Public-Exposure | CoNote/CSPM `PublicExposure` | Max > 0 over 15 min | OK |
| CoNote-CSPM-Critical-Findings | CoNote/CSPM `CriticalFindings` (**real count** from the scan, muted risks excluded) | Max > 0 over 15 min | **ALARM**: 2 open criticals (F-01/F-02) |
| CoNote-CSPM-Scan-Missing | CoNote/CSPM `ScanCompleted` | Sum < 1 per hour, 2 h, **missing = breaching** | OK |
| CoNote-Custodian-detect-public-ssh-access | **CloudMaid** `ResourceCount` (dims discovered: Policy, Scope, ResType) | Max > 0 over 1 h | OK |
| EventBridge `conote-cspm-risky-config-change` | CloudTrail events | 7 risky API calls | — |

**Alert-fatigue control:** accepted risks are listed in `prowler/mutelist.yaml` (each linked to an exception). Prowler reports them as **MUTED** (33 on 23 Nov), still visible, but they no longer count towards the alarms. Without it, `Critical-Findings` would never return to OK.

## 3. Demonstration: alert test (2026-11-23, UTC)

| Step | Time | Evidence |
|---|---|---|
| Baseline | 12:40:11 | both alarms OK |
| **Violation**: `Ezra` opens 22/tcp to 0.0.0.0/0 on `conote-admin-sg` | 12:40:30 (CloudTrail `AuthorizeSecurityGroupIngress` 12:40:53) | drift script, CloudTrail |
| Real-time EventBridge email "RISKY CHANGE…" | _(time from mailbox screenshot)_ | email |
| **Detection by scan**: exposure check `ssh=1 total=1`; Custodian `detect-public-ssh-access 1` | 12:43:26 | log, `reports/custodian/…` |
| **Alarm** `Public-Exposure` OK → ALARM (CloudWatch history) | 12:44:19 | alarm history, ALARM email |
| Investigation: CloudTrail shows **who** (`Ezra`) and **when** | 12:5x | log line |
| **Remediation** CHG-002 (remediator role + MFA): `removepermissions resources:1` | 12:51:53 | `registers/remediation_log.csv` |
| Recheck: `total=0` | 12:53:30 | log |
| **Alarm back to OK** (history) | 13:01:19 | alarm history, OK email |
| Custodian hourly alarm back to OK | after the next hourly runs (1 h window) | `state` output |

### Measured times

| Metric | From → to | Duration |
|---|---|---|
| Time to detect, by scan | violation 12:40:53 → detection 12:43:26 | **2 min 33 s** (manual run; with cron worst case ≈ 15 min) |
| Time to alert | violation → ALARM 12:44:19 | **3 min 26 s** |
| Time to correct (exposure window) | violation → fix 12:51:53 | **≈ 11 min** |
| Time from alert to fix | ALARM → fix | **≈ 7.5 min** (incl. investigation and MFA approval) |
| Time to recover | fix → alarm OK 13:01:19 | **≈ 9.5 min**: alarm needs the "1" to leave its 15-min window |

**Lesson:** alarm periods decide how fast alarms **fire and clear**. The 15-min alarm cleared after about 10 min; the hourly Custodian alarm took over an hour. Short windows suit critical exposure; long windows suit trends.

## 4. Problems met

| # | Problem | Cause | Fix |
|---|---|---|---|
| P1 | GitHub run failed: `Not authorized to perform sts:AssumeRoleWithWebIdentity` | GitHub now issues an **immutable OIDC subject** `repo:Ezra-410@186315605/co-note-cspm@1462202519:ref:refs/heads/main` (owner and repo IDs). The trust policy expected the old name-only form. Found via **CloudTrail** (failed AssumeRoleWithWebIdentity shows the real `sub`). | Terraform trust condition updated to the ID-based subject → run 45176346105 ✅. More secure: a deleted-and-recreated repo with the same name can no longer assume the role. |
| P2 | Alarm would stay red forever on accepted risks | criticals counted whether accepted or not | Prowler mutelist + MUTED status |
| P3 | Scheduled Custodian checks could report stale data | 15-min API cache (M3) | `--cache-period 0` |
| P4 | cron stops when WSL closes | laptop-based scheduler | cloud scheduler + Scan-Missing heartbeat |

---

## 5. Investigation questions

**1. Periodic scanning vs real-time monitoring?**
**Periodic** = a guard who checks every door every 15 minutes (cron, Prowler, Custodian). **Real-time** = a sensor that beeps the moment a door opens (CloudTrail → EventBridge). Periodic sees **everything** but late; real-time sees **changes** immediately but not the overall state. We use both.

**2. Why is a daily scan not enough for critical resources?**
An SSH port opened at 02:05, just after the daily scan, stays exposed for up to **24 hours**. Internet scanners find open SSH in minutes. Critical exposure needs the 15-minute check and the real-time rule. Ours raised an alarm **3½ minutes** after the change.

**3. Event vs metric?**
An **event** is one thing that happened: "Ezra called AuthorizeSecurityGroupIngress at 12:40:53". A **metric** is a number measured over time: "PublicExposure = 1 at 12:43". Events say **what and who**; metrics say **how much**, and can be compared to a threshold.

**4. What is EventBridge for?**
It's AWS's **event router**: it receives events (like CloudTrail API calls), matches them against rules, and sends matches to targets. Our rule sends "security group opened / bucket made public" straight to SNS → email. It can also run things on a schedule.

**5. How does CloudTrail help investigate a change?**
It's the account's **CCTV recording**: who (user or role), what (API call and parameters), when, and from where (IP). It told us `Ezra` opened the port at 12:40:53, and also revealed the exact OIDC subject GitHub was sending when the login failed.

**6. Alert vs security incident?**
An **alert** is a **signal** that something may be wrong ("SSH open"). An **incident** is a **confirmed** event that harms or threatens security and needs response. Many alerts are tests, false positives or approved changes. An analyst investigates an alert and decides whether it becomes an incident.

**7. How to handle alerts that keep repeating?**
Don't just close them again. Find the **cause**: who or what keeps re-creating the problem (CloudTrail), then fix that process or person's access, or the IaC code. If the condition is accepted, **mute it with a documented exception**. Our register counts recurrences: F-SSH-02 has `recurrence_count = 1`.

**8. What if the monitoring service itself fails?**
You get **silence, which looks exactly like "all good"**. That's why we have the **Scan-Missing** alarm: if no scan reports for 2 hours, *missing data = alarm*. A second scheduler (GitHub) also keeps scanning when the laptop is off.

**9. How to avoid alert fatigue?**
- Alert only on what needs **action**: critical exposure, not 38 Low findings.
- **Mute accepted risks** (mutelist, 33 muted) with expiry dates.
- Group by root cause.
- Use sensible thresholds and windows.
- Send OK messages so people know when it's over.
- Review noisy rules regularly.

**10. What should a security notification contain?**
- **What** happened (event or rule)
- **Which** resource, account and region
- **Who** did it, and from where
- **When**
- **Severity**
- **What to do** next (runbook)

Our EventBridge message includes event, account, region, time, user, IP, group/bucket and "follow the remediation runbook".

**11. How to identify who made a change?**
**CloudTrail** `userIdentity`: IAM user, assumed role and session name, or service. Our lookup showed `Ezra` for the drift and the remediator session for the fix. Unique users and per-purpose roles make this answer clear. A shared admin account would make it useless.

**12. How to measure time between detection and correction?**
Record timestamps at each step: violation (CloudTrail), detection (scan log), alert (alarm history), fix (remediation log), recovery (alarm history). Subtract them, as in section 3: **detect 2 min 33 s · alert 3 min 26 s · fix 11 min · recover 9.5 min**. Over many incidents these become **MTTD / MTTR**, key security KPIs.
