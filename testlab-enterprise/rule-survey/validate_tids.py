"""
validate_tids.py
----------------
Kiem tra cac Technique ID trong coverage.tsv co ton tai trong
danh sach chinh thuc cua MITRE (technique_names.txt) hay khong.

Output ra console + file invalid_tids.csv
"""

import csv
import re
from pathlib import Path
from collections import defaultdict

BASE            = Path(__file__).parent
COVERAGE        = BASE / "coverage.tsv"
TECHNIQUE_NAMES = BASE / "../../mitre-knowledge-base/technique_names.txt"
OUTPUT          = BASE / "invalid_tids.csv"


# ---------------------------------------------------------------------------
# 1. Load valid TIDs from technique_names.txt
#    Format each line: "T1059.001 - Command and Scripting Interpreter: PowerShell",
# ---------------------------------------------------------------------------
def load_valid_tids(path):
    valid = {}
    tid_re = re.compile(r'"(T\d+(?:\.\d+)?)\s+-\s+(.+?)"')
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = tid_re.search(line)
            if m:
                valid[m.group(1)] = m.group(2).strip()
    return valid


# ---------------------------------------------------------------------------
# 2. Collect all (tid, rule_name) pairs from coverage.tsv
# ---------------------------------------------------------------------------
def load_coverage_tids(path):
    """
    Returns list of (rule_name, tid) for every TID found in Technique column.
    Deduplicates per row but keeps one entry per (rule, tid) pair.
    """
    entries = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            rule_name  = row.get("Rule name", "").strip()
            tech_field = row.get("Technique", "").strip()
            if not rule_name or not tech_field:
                continue
            seen = set()
            for tid in tech_field.split(","):
                tid = tid.strip()
                if tid and tid not in seen:
                    seen.add(tid)
                    entries.append((rule_name, tid))
    return entries


# ---------------------------------------------------------------------------
# 3. Main
# ---------------------------------------------------------------------------
def main():
    valid_tids = load_valid_tids(TECHNIQUE_NAMES)
    print(f"Valid TIDs loaded from MITRE list: {len(valid_tids)}")

    entries = load_coverage_tids(COVERAGE)
    all_tids_in_coverage = {tid for _, tid in entries}
    print(f"Unique TIDs found in coverage.tsv : {len(all_tids_in_coverage)}")

    # Find invalid TIDs
    invalid_tids = {tid for tid in all_tids_in_coverage if tid not in valid_tids}

    if not invalid_tids:
        print("\nAll TIDs are valid.")
        return

    # Map invalid TID -> rules that use it
    tid_to_rules = defaultdict(list)
    for rule_name, tid in entries:
        if tid in invalid_tids:
            if rule_name not in tid_to_rules[tid]:
                tid_to_rules[tid].append(rule_name)

    # Print to console
    print(f"\nInvalid / deprecated TIDs found: {len(invalid_tids)}\n")
    print(f"{'TID':<20} {'Rule count':>10}  Rules")
    print("-" * 80)
    for tid in sorted(invalid_tids):
        rules = tid_to_rules[tid]
        print(f"{tid:<20} {len(rules):>10}  {', '.join(rules[:3])}{'...' if len(rules) > 3 else ''}")

    # Write CSV
    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["invalid_tid", "rule_count", "rules"])
        for tid in sorted(invalid_tids):
            rules = tid_to_rules[tid]
            writer.writerow([tid, len(rules), " | ".join(rules)])

    print(f"\nOutput written to: {OUTPUT}")


if __name__ == "__main__":
    main()
