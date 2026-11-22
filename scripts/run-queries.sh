#!/usr/bin/env bash
# =============================================================================
# Run every statement of the Steampipe query files, one at a time.
# Steampipe v2 refuses a file holding several statements ("cannot insert
# multiple commands into a prepared statement"), so the files are split on ";".
# The "-- comment" lines just above a statement are printed as its title.
# Output is appended to reports/m4/m4-queries-<UTC date>.txt (kept over time).
# Usage: scripts/run-queries.sh [file.sql ...]   (default: steampipe/queries/0*.sql)
# =============================================================================
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/co-note-cspm}"
OUT="$PROJECT_DIR/reports/m4/m4-queries-$(date -u +%Y%m%d-%H%M).txt"
mkdir -p "$(dirname "$OUT")"
[ $# -gt 0 ] || set -- "$PROJECT_DIR"/steampipe/queries/0*.sql

for f in "$@"; do
  python3 - "$f" <<'PY' > /tmp/stmts.$$
import sys
text = open(sys.argv[1]).read()
for stmt in text.split(";"):
    lines = stmt.strip().splitlines()
    title = [l[2:].strip() for l in lines if l.strip().startswith("--")]
    sql = " ".join(l for l in lines if l.strip() and not l.strip().startswith("--"))
    if sql:
        print((title[-1] if title else "query") + "\t" + sql)
PY
  echo "################ $(basename "$f")" | tee -a "$OUT"
  while IFS=$'\t' read -r title sql; do
    echo "== $title" | tee -a "$OUT"
    steampipe query "$sql" 2>&1 | tee -a "$OUT"
  done < /tmp/stmts.$$
  rm -f /tmp/stmts.$$
done
echo "Saved: $OUT"
