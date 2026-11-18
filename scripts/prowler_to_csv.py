#!/usr/bin/env python3
"""Normalise a Prowler OCSF JSON report for the CSPM dashboard and metrics.

Usage:  prowler_to_csv.py <prowler-output-dir> <data-dir>

Writes (comma-separated, header row, readable by the Steampipe CSV plugin):
  <data-dir>/prowler_findings.csv   one row per finding of the LATEST scan
  <data-dir>/scan_history.csv       one row appended per scan (trend over time)
Prints a JSON summary on stdout: {"critical": n, "high": n, ... }

Statuses are kept as Prowler reports them:
  FAIL   = check ran and the resource violates it
  PASS   = check ran and the resource complies
  MANUAL = check needs a human (cannot be decided automatically)
A check that could not run (access denied, service not available) produces NO
row - so "no finding" never means "compliant" (see docs, CSPM-12).
"""
import csv
import glob
import json
import os
import sys
from datetime import datetime, timezone

FIELDS = [
    "scan_time", "check_id", "check_title", "severity", "status", "service",
    "resource_uid", "resource_name", "region", "account_id",
    "cis", "nist_800_53", "frameworks", "remediation",
]


def latest_ocsf(path: str) -> str:
    files = sorted(glob.glob(os.path.join(path, "**", "*.ocsf.json"), recursive=True),
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
    os.makedirs(data_dir, exist_ok=True)
    src = latest_ocsf(src_dir)
    with open(src, encoding="utf-8") as fh:
        findings = json.load(fh)

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows, counts = [], {"critical": 0, "high": 0, "medium": 0, "low": 0,
                        "informational": 0, "fail": 0, "pass": 0, "manual": 0}
    for f in findings:
        status = f.get("status_code", "")
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
            "cis": pick(comp, "CIS-"),
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

    with open(os.path.join(data_dir, "prowler_findings.csv"), "w", newline="", encoding="utf-8") as out:
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
        w.writerow([scan_time, "prowler", counts["critical"], counts["high"], counts["medium"],
                    counts["low"], counts["fail"], counts["pass"], counts["manual"],
                    os.path.basename(src)])

    counts["report"] = src
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
