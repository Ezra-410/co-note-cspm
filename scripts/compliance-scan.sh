#!/usr/bin/env bash
# Weekly compliance assessment: CIS AWS Foundations 5.0 + NIST SP 800-53 rev 5
# (identifiers checked with: prowler aws --list-compliance)
exec "$(dirname "$0")/prowler-scan.sh" --compliance cis_5.0_aws nist_800_53_revision_5_aws
