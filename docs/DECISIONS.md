# Decisions log (Lab 03)

| # | Decision | Why | Trade-off |
|---|---|---|---|
| D1 | AWS Free plan account, single region eu-west-1 | No AWS access in Lab 02; credits cover a small environment; region used by the lab examples | Free plan closes after 6 months; other regions not deployed (Prowler limited to eu-west-1 + global IAM) |
| D2 | Small dedicated "Co-note lab" environment instead of the full Lab 02 design (no ALB, NAT, RDS, WAF) | Those services consume credits quickly; CSPM needs real resources, not every resource | Fewer resource types to assess; documented in limitations |
| D3 | Separate read-only audit role, MFA-protected remediator role | Scanners must not be able to change anything; every correction needs a human | One extra profile to configure |
| D4 | Detection and remediation policies in separate files | A detection run can never modify resources by mistake | Two runs instead of one |
| D5 | Two alert paths: scan metrics → CloudWatch alarm, and CloudTrail → EventBridge → SNS | Periodic scans can miss a change for up to 15 min; EventBridge reacts to the API call itself | EventBridge only sees the change, not whether the result is insecure → both are needed |
| D6 | Scheduled scans both by cron (laptop, required by the lab) and GitHub Actions + OIDC | A laptop is off at night; Actions runs in the cloud with no stored AWS keys | GitHub schedules can be delayed by a few minutes |
| D7 | Drift injected by hand with `scripts/simulate-drift.sh` | Reproduces the lab scenario: a change made outside Terraform and outside the pipeline | Must be run only in this test account |
| D8 | Compliance "pass rate" defined explicitly as PASS ÷ (PASS+FAIL), MANUAL excluded | The lab forbids inventing a score; the official per-control score stays the Powerpipe/Prowler benchmark | Internal metric, not comparable with other tools' scores |
