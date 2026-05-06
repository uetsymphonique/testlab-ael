"""
counting_rules.py
-----------------
Dem so rule trong coverage.tsv cho moi technique thuoc scope
cua Scenario 1.md va/hoac Scenario 2.md.

Output: rule_coverage.csv
Columns:
    technique_id    - TID (e.g. T1059.001)
    technique_name  - Ten day du
    tactic          - Tactic section (tu scenario file)
    in_scenario1    - True/False
    in_scenario2    - True/False
    rule_count      - So rule cover technique nay
    rules           - Danh sach rule name (phan tach bang " | ")
"""

import csv
import re
from pathlib import Path
from collections import defaultdict

BASE        = Path(__file__).parent
COVERAGE    = BASE / "coverage_clean.tsv"
SCENARIO1   = BASE / "../mitre-outline/Scenario 1.md"
SCENARIO2   = BASE / "../mitre-outline/Scenario 2.md"
OUTPUT      = BASE / "rule_coverage.csv"


# ---------------------------------------------------------------------------
# 1. Parse technique list from a scenario markdown file
# ---------------------------------------------------------------------------
def parse_scenario(md_path):
    """
    Returns:
        { "T1059.001": {"name": "...", "tactic": "Execution"}, ... }
    """
    techniques = {}
    current_tactic = "Unknown"
    tech_line = re.compile(r"^[+\-*]\s+(T\d+(?:\.\d+)?)\s+-\s+(.+)$")

    with open(md_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            # ## heading = tactic section
            if line.startswith("## "):
                current_tactic = line[3:].strip()
                continue
            m = tech_line.match(line)
            if m:
                tid, name = m.group(1), m.group(2).strip()
                if tid not in techniques:
                    techniques[tid] = {"name": name, "tactic": current_tactic}
    return techniques


# ---------------------------------------------------------------------------
# 2. Parse coverage.tsv — map each unique TID to list of rule names
# ---------------------------------------------------------------------------
def parse_coverage(tsv_path):
    """
    Returns:
        { "T1059.001": ["Rule_A", "Rule_B", ...], ... }
    Technique field may contain comma-separated, duplicated TIDs — deduplicated per row.
    """
    tid_to_rules = defaultdict(set)

    with open(tsv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            rule_name  = row.get("Rule name", "").strip()
            tech_field = row.get("Technique", "").strip()
            if not rule_name or not tech_field:
                continue
            # Split, strip, deduplicate
            tids = {t.strip() for t in tech_field.split(",") if t.strip()}
            for tid in tids:
                tid_to_rules[tid].add(rule_name)

    return {k: sorted(v) for k, v in tid_to_rules.items()}


# ---------------------------------------------------------------------------
# 3. Build output
# ---------------------------------------------------------------------------
def main():
    s1 = parse_scenario(SCENARIO1)
    s2 = parse_scenario(SCENARIO2)
    coverage = parse_coverage(COVERAGE)

    # Union of all in-scope TIDs
    all_tids = sorted(set(s1) | set(s2))

    rows = []
    for tid in all_tids:
        in_s1  = tid in s1
        in_s2  = tid in s2
        # Prefer name/tactic from S1, fall back to S2
        meta   = s1.get(tid) or s2.get(tid)
        tactic = meta["tactic"]
        name   = meta["name"]

        rules      = coverage.get(tid, [])
        rule_count = len(rules)
        rule_names = " | ".join(rules)

        rows.append({
            "technique_id":   tid,
            "technique_name": name,
            "tactic":         tactic,
            "in_scenario1":   in_s1,
            "in_scenario2":   in_s2,
            "rule_count":     rule_count,
            "rules":          rule_names,
        })

    # Sort by tactic then technique_id
    rows.sort(key=lambda r: (r["tactic"], r["technique_id"]))

    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "technique_id", "technique_name", "tactic",
            "in_scenario1", "in_scenario2",
            "rule_count", "rules"
        ])
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    covered = sum(1 for r in rows if r["rule_count"] > 0)
    total   = len(rows)
    print(f"Output  : {OUTPUT}")
    print(f"Total techniques in scope : {total}")
    print(f"Techniques with >=1 rule  : {covered}  ({covered / total * 100:.1f}%)")
    print(f"Techniques with 0 rules   : {total - covered}")


if __name__ == "__main__":
    main()
