#!/usr/bin/env python3
"""
check.py — Mark techniques as done in a Scenario scope list.

Reads Reference Tables from one or more plan .md files, then updates the target
scope file (Scenario 1/2) checkboxes:

  - [x]  technique + tactic both match plan  (exact hit)
  - [~]  technique matches plan but under a different tactic in the plan
  - [ ]  not covered by any plan file (unchanged)

Techniques in the plan that are absent from the scope file entirely are written
to <scope>_out_of_scope.csv.

Usage:
    python check.py --scope <Scenario.md> <plan1.md> [plan2.md ...]
    python check.py --reset --scope <Scenario.md>

Options:
    --reset   Undo all marks in the scope file: revert [x]/[~] → [ ] and
              strip <!-- plan tactic: ... --> annotations. Plan files are
              not required when using --reset.

Examples:
    python check.py --scope "Scenario 1.md" Phase1.md Phase2.md
    python check.py --scope "Scenario 2.md" Phase1.md Phase2.md Phase3.md
    python check.py --reset --scope "Scenario 1.md"
"""

import sys
import re
import csv
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Markdown table helpers
# ---------------------------------------------------------------------------

def _split_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("||"):
        s = s[2:]
    elif s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _is_separator(line: str) -> bool:
    s = line.strip().lstrip("|")
    return bool(re.fullmatch(r"[\s\-|]+", s))


def _is_table_row(line: str) -> bool:
    s = line.strip()
    return s.startswith("|") or s.startswith("||")


def _find_col(headers: list[str], aliases: set[str]) -> int | None:
    for i, h in enumerate(headers):
        if h.strip().lower() in aliases:
            return i
    return None


def _norm(s: str) -> str:
    return s.strip().lower()


# ---------------------------------------------------------------------------
# Parse plan files → covered sets
# ---------------------------------------------------------------------------

def extract_plan_techniques(filepath: Path) -> list[tuple[str, str, str, str]]:
    """
    Return list of (norm_tactic, tech_id, tech_name, category) from all Reference Tables.
    category is the raw value of the "Category" column (e.g. "Calibrated - Not Benign").
    """
    lines = filepath.read_text(encoding="utf-8").splitlines()
    results = []
    i = 0
    while i < len(lines):
        if re.match(r"#{1,4}\s+Reference\s+Tables", lines[i], re.IGNORECASE):
            i += 1
            while i < len(lines) and not _is_table_row(lines[i]):
                i += 1
            if i >= len(lines):
                break
            headers = _split_row(lines[i])
            i += 1
            if i < len(lines) and _is_table_row(lines[i]) and _is_separator(lines[i]):
                i += 1
            tac_idx   = _find_col(headers, {"tactic", "tactics"})
            tid_idx   = _find_col(headers, {"technique id", "technique_id"})
            tname_idx = _find_col(headers, {"technique name", "technique_name"})
            cat_idx   = _find_col(headers, {"category"})
            if tid_idx is None:
                continue
            while i < len(lines) and _is_table_row(lines[i]):
                cells = _split_row(lines[i])
                while len(cells) < len(headers):
                    cells.append("")
                tid  = cells[tid_idx].strip()
                tac  = cells[tac_idx].strip()  if tac_idx   is not None else ""
                name = cells[tname_idx].strip() if tname_idx is not None else ""
                cat  = cells[cat_idx].strip()   if cat_idx   is not None else ""
                if re.match(r"T\d{4}", tid):
                    results.append((_norm(tac), tid, name, cat))
                i += 1
        else:
            i += 1
    return results


def _is_calibrated(category: str) -> bool | None:
    """
    True  → category starts with "Calibrated"
    False → category starts with "Not Calibrated"
    None  → unknown / empty
    """
    c = category.strip().lower()
    if c.startswith("not calibrated"):
        return False
    if c.startswith("calibrated"):
        return True
    return None


# ---------------------------------------------------------------------------
# Scope file helpers
# ---------------------------------------------------------------------------

TECH_LINE_RE = re.compile(
    r"^(?P<indent>\s*)-\s+\[(?P<state>[ x~])\]\s+(?P<tid>T\d{4}(?:\.\d+)?)\b.*$"
)
SECTION_RE = re.compile(r"^(?P<hashes>#{1,4})\s+(?P<title>.+)$")


def collect_scope_pairs(scope_path: Path) -> set[tuple[str, str]]:
    """Return all (norm_tactic, tech_id) present in scope file."""
    lines = scope_path.read_text(encoding="utf-8").splitlines()
    pairs: set[tuple[str, str]] = set()
    cur = ""
    for line in lines:
        m = SECTION_RE.match(line.rstrip())
        if m and len(m.group("hashes")) >= 2:
            cur = _norm(m.group("title"))
        tm = TECH_LINE_RE.match(line.rstrip())
        if tm:
            pairs.add((cur, tm.group("tid")))
    return pairs


# ---------------------------------------------------------------------------
# Core updater
# ---------------------------------------------------------------------------

def update_scope_file(
    scope_path: Path,
    covered: set[tuple[str, str]],
    covered_tids: dict[str, list[str]],
) -> tuple[int, int, int]:
    """
    Rewrite scope_path in-place.
      [x]  exact (tactic, tech) match
      [~]  tech matches but tactic differs — appends  <!-- plan tactic: X -->
      [ ]  untouched

    Returns (newly_exact, newly_mismatch, already_done).
    """
    lines = scope_path.read_text(encoding="utf-8").splitlines(keepends=True)
    cur_tactic  = ""
    n_exact     = 0
    n_mismatch  = 0
    n_already   = 0
    out = []

    for line in lines:
        sec_m = SECTION_RE.match(line.rstrip())
        if sec_m and len(sec_m.group("hashes")) >= 2:
            cur_tactic = _norm(sec_m.group("title"))

        tech_m = TECH_LINE_RE.match(line.rstrip("\n\r"))
        if tech_m:
            tid   = tech_m.group("tid")
            state = tech_m.group("state")
            key   = (cur_tactic, tid)

            if key in covered:
                if state == " ":
                    line = line.replace("- [ ]", "- [x]", 1)
                    n_exact += 1
                elif state in ("x", "~"):
                    n_already += 1
            elif tid in covered_tids and state == " ":
                plan_tacs = ", ".join(t.title() for t in covered_tids[tid])
                eol = "\n" if line.endswith("\n") else ""
                line = (
                    line.rstrip("\n\r").replace("- [ ]", "- [~]", 1)
                    + f"  <!-- plan tactic: {plan_tacs} -->"
                    + eol
                )
                n_mismatch += 1

        out.append(line)

    scope_path.write_text("".join(out), encoding="utf-8")
    return n_exact, n_mismatch, n_already


# ---------------------------------------------------------------------------
# Reset helper
# ---------------------------------------------------------------------------

PLAN_TACTIC_COMMENT_RE = re.compile(r"\s*<!--\s*plan tactic:[^>]*-->")


def reset_scope_file(scope_path: Path) -> tuple[int, int]:
    """
    Revert all marks written by update_scope_file:
      [x] → [ ]
      [~] → [ ]   (also strips <!-- plan tactic: ... --> annotation)

    Returns (n_unchecked, n_unmismatch).
    """
    lines = scope_path.read_text(encoding="utf-8").splitlines(keepends=True)
    n_unchecked  = 0
    n_unmismatch = 0
    out = []

    for line in lines:
        tech_m = TECH_LINE_RE.match(line.rstrip("\n\r"))
        if tech_m:
            state = tech_m.group("state")
            if state == "x":
                line = line.replace("- [x]", "- [ ]", 1)
                n_unchecked += 1
            elif state == "~":
                line = line.replace("- [~]", "- [ ]", 1)
                stripped = line.rstrip("\n\r")
                eol = line[len(stripped):]  # preserve original line ending
                line = PLAN_TACTIC_COMMENT_RE.sub("", stripped).rstrip() + eol
                n_unmismatch += 1
        out.append(line)

    scope_path.write_text("".join(out), encoding="utf-8")
    return n_unchecked, n_unmismatch


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if "--scope" not in args:
        print(__doc__)
        sys.exit(0)

    reset_mode = "--reset" in args
    args = [a for a in args if a != "--reset"]

    idx = args.index("--scope")
    if idx + 1 >= len(args):
        print("[!] --scope requires a filename argument.", file=sys.stderr)
        sys.exit(1)

    scope_file = Path(args[idx + 1])
    plan_files = [Path(a) for a in args if a != "--scope" and a != args[idx + 1]]

    if not scope_file.exists():
        print(f"[!] Scope file not found: {scope_file}", file=sys.stderr)
        sys.exit(1)

    # ── reset mode ──────────────────────────────────────────────────────────
    if reset_mode:
        n_unchk, n_unmis = reset_scope_file(scope_file)
        print(f"[+] Reset {scope_file.name}")
        print(f"    [ ] Unchecked [x]   : {n_unchk}")
        print(f"    [ ] Cleared  [~]    : {n_unmis}")
        return

    # ── normal check mode ───────────────────────────────────────────────────
    if not plan_files:
        print("[!] No plan files specified. Provide at least one plan .md file.", file=sys.stderr)
        sys.exit(1)

    missing = [p for p in plan_files if not p.exists()]
    if missing:
        for p in missing:
            print(f"[!] Plan file not found: {p}", file=sys.stderr)
        sys.exit(1)

    # Parse all plan files
    covered: set[tuple[str, str]]          = set()
    covered_tids: dict[str, list[str]]     = defaultdict(list)
    name_map: dict[str, str]               = {}
    total_calibrated   = 0
    total_uncalibrated = 0
    total_unknown_cat  = 0

    for p in plan_files:
        rows = extract_plan_techniques(p)
        cal = sum(1 for _, _, _, cat in rows if _is_calibrated(cat) is True)
        uncal = sum(1 for _, _, _, cat in rows if _is_calibrated(cat) is False)
        unk   = len(rows) - cal - uncal
        total_calibrated   += cal
        total_uncalibrated += uncal
        total_unknown_cat  += unk
        cal_str = f"  (Calibrated: {cal}, Not Calibrated: {uncal}" + (f", Unknown: {unk}" if unk else "") + ")"
        print(f"[*] {p.name}: {len(rows)} rows{cal_str}")
        for tac, tid, name, cat in rows:
            covered.add((tac, tid))
            if tac not in covered_tids[tid]:
                covered_tids[tid].append(tac)
            if tid not in name_map and name:
                name_map[tid] = name

    total_pairs = len(covered)
    print(f"[*] Total unique (tactic, tech) pairs: {total_pairs}")
    unk_str = f", Unknown: {total_unknown_cat}" if total_unknown_cat else ""
    print(f"[*] Calibrated: {total_calibrated}, Not Calibrated: {total_uncalibrated}{unk_str}")

    # Find plan techniques absent from scope entirely
    scope_pairs  = collect_scope_pairs(scope_file)
    out_of_scope = covered - scope_pairs

    # Update scope file
    n_exact, n_mismatch, n_already = update_scope_file(scope_file, covered, covered_tids)

    print(f"\n[+] {scope_file.name}")
    print(f"    [x] Newly exact-matched  : {n_exact}")
    print(f"    [~] Tactic mismatch      : {n_mismatch}")
    print(f"    Already done             : {n_already}")
    print(f"    Not in scope at all      : {len(out_of_scope)}")

    # Write out-of-scope CSV
    if out_of_scope:
        rows_oos = sorted(
            [{"tactic": tac.title(), "tech_id": tid, "tech_name": name_map.get(tid, "")}
             for tac, tid in out_of_scope],
            key=lambda r: (r["tactic"], r["tech_id"]),
        )
        csv_path = scope_file.with_name(scope_file.stem + "_out_of_scope.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["tactic", "tech_id", "tech_name"])
            writer.writeheader()
            writer.writerows(rows_oos)
        print(f"\n[+] Out-of-scope CSV: {csv_path.name}")
        for r in rows_oos:
            print(f"    {r['tactic']:30} {r['tech_id']:12} {r['tech_name']}")


if __name__ == "__main__":
    main()
