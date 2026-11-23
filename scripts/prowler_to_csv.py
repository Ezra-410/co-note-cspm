#!/usr/bin/env python3
"""Normalise a Prowler OCSF JSON report for the CSPM dashboard and metrics.

Usage:  prowler_to_csv.py <prowler-output-dir> <data-dir> [full|compliance]

Writes (comma-separated, header row, readable by the Steampipe CSV plugin):
  <data-dir>/prowler_findings.csv   one row per finding of the LATEST scan
  <data-dir>/scan_history.csv       one row appended per scan (trend over time)
Prints a JSON summary on stdout: {"critical": n, "high": n, ... }

Statuses are kept as Prowler reports them:
  FAIL   = check ran and the resource violates it
  PASS   = check ran and the resource complies
  MANUAL = check needs a human (cannot be decided automatically)
  MUTED  = FAIL on an accepted risk (prowler/mutelist.yaml -> exceptions.csv)
A check that could not run (access denied, service not available) produces NO
row - so "no finding" never means "compliant" (see docs, CSPM-12).
"""
import csv
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

FIELDS = [
    "scan_time", "check_id", "check_title", "severity", "status", "service",
    "resource_uid", "resource_name", "region", "account_id",
    "cis", "nist_800_53", "frameworks", "remediation",
]


def latest_ocsf(path: str) -> str:
    # Main report only: prowler-output-<account>-<timestamp>.ocsf.json in the
    # report folder itself. The compliance/ sub-folder also holds *.ocsf.json
    # files (one per framework) - they must NOT be used as the main result.
    files = sorted((f for f in glob.glob(os.path.join(path, "prowler-output-*.ocsf.json"))
                    if re.fullmatch(r"prowler-output-\d+-\d+\.ocsf\.json", os.path.basename(f))),
                   key=os.path.getmtime)
    if not files:
        sys.exit(f"no *.ocsf.json found under {path}")
    return files[-1]


def pick(compliance: dict, prefix: str) -> str:
    """Join requirement ids of the newest framework version starting with prefix."""
    keys = sorted(k for k in compliance if k.upper().startswith(prefix))
    if not keys:
        return ""
    return f"{keys[-1]}:" + "|".join(compliance[keys[-1]])


def main() -> None:
    src_dir, data_dir = sys.argv[1], sys.argv[2]
    # "full" scans feed the dashboard; "compliance" scans (subset of checks)
    # are written to their own file so they never overwrite the full picture.
    kind = sys.argv[3] if len(sys.argv) > 3 else "full"
    findings_file = "prowler_findings.csv" if kind == "full" else "prowler_compliance_findings.csv"
    os.makedirs(data_dir, exist_ok=True)
    src = latest_ocsf(src_dir)
    with open(src, encoding="utf-8") as fh:
        findings = json.load(fh)

    # Real scan time from the report (epoch seconds, UTC); fallback = now.
    epoch = findings[0].get("time") if findings else None
    when = datetime.fromtimestamp(epoch, timezone.utc) if epoch else datetime.now(timezone.utc)
    scan_time = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    rows, counts = [], {"critical": 0, "high": 0, "medium": 0, "low": 0,
                        "informational": 0, "fail": 0, "pass": 0, "manual": 0, "muted": 0}
    for f in findings:
        status = f.get("status_code", "")
        # Findings muted by prowler/mutelist.yaml (accepted risks) keep their
        # row but get status MUTED, so they never trigger the alarms.
        if f.get("status") == "Suppressed" and status == "FAIL":
            status = "MUTED"
        sev = (f.get("severity") or "").lower()
        res = (f.get("resources") or [{}])[0]
        comp = (f.get("unmapped") or {}).get("compliance") or {}
        rows.append({
            "scan_time": scan_time,
            "check_id": (f.get("metadata") or {}).get("event_code", ""),
            "check_title": (f.get("finding_info") or {}).get("title", ""),
            "severity": f.get("severity", ""),
            "status": status,
            "service": (res.get("group") or {}).get("name", ""),
            "resource_uid": res.get("uid", ""),
            "resource_name": res.get("name", ""),
            "region": res.get("region", ""),
            "account_id": ((f.get("cloud") or {}).get("account") or {}).get("uid", ""),
            # Pin CIS to 5.0 (same version as the Powerpipe benchmark cis_v500)
            # so both tools are compared on the same benchmark; newest otherwise.
            "cis": pick(comp, "CIS-5.0") or pick(comp, "CIS-"),
            "nist_800_53": pick(comp, "NIST-800-53-REVISION-5") or pick(comp, "NIST-800-53"),
            "frameworks": "|".join(sorted(comp)),
            "remediation": ((f.get("remediation") or {}).get("desc") or "").replace("\n", " ")[:300],
        })
        if status == "FAIL":
            counts["fail"] += 1
            if sev in counts:
                counts[sev] += 1
        elif status == "PASS":
            counts["pass"] += 1
        elif status == "MANUAL":
            counts["manual"] += 1
        elif status == "MUTED":
            counts["muted"] += 1

    with open(os.path.join(data_dir, findings_file), "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    hist = os.path.join(data_dir, "scan_history.csv")
    new = not os.path.exists(hist)
    with open(hist, "a", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        if new:
            w.writerow(["scan_time", "tool", "critical", "high", "medium", "low",
                        "fail", "pass", "manual", "source_report"])
        w.writerow([scan_time, "prowler" if kind == "full" else "prowler-compliance", counts["critical"], counts["high"], counts["medium"],
                    counts["low"], counts["fail"], counts["pass"], counts["manual"],
                    os.path.basename(src)])

    counts["report"] = src
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
