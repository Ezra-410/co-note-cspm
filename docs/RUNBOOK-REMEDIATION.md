# Runbook · Controlled remediation

Applies to every Cloud Custodian policy with an `actions:` block.
Detection runs automatically; **correction never does** without these steps.

1. **Detect** – finding raised by Prowler, Custodian (hourly / 15 min), Steampipe or an EventBridge alert.
2. **Register** – add a row to `registers/findings_register.csv` (status `open`).
3. **Investigate** – who made the change and when:
   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<sg-id or bucket> --max-results 5
   ```
4. **Impact check** – does a legitimate workflow depend on it? (Co-note admin access = SSM Session Manager, so no SSH rule is ever legitimate.)
5. **Dry run** with the remediator role:
   ```bash
   AWS_PROFILE=conote-remediator custodian run --cache-period 0 --dryrun -s output/dryrun policies/remediate-<x>.yml
   ```
6. **Approval** – infrastructure owner approves; record in `registers/remediation_log.csv`. Status → `in_progress`.
7. **Execute** – same command without `--dryrun` (MFA code requested by the profile).
8. **Verify** – AWS CLI describe call + detection policy again **with `--cache-period 0`** (Custodian caches API results for 15 min by default, so a re-run would show the old state) + Steampipe query; then Prowler.
9. **Close** – status `resolved`, `resolved_at`, evidence paths (before/after reports).
10. **Recurrence** – if the same resource comes back, increase `recurrence_count` and fix the *cause* (who/what re-creates it), not only the symptom.

Rollback of a remediation: re-add the exact rule from the dry-run `resources.json` (it records the removed permission).
