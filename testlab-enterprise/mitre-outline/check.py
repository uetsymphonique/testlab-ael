#!/usr/bin/env python3
"""
check.py — Mark techniques as done in a Scenario scope list.

Reads Reference Tables from one or more plan .md files, then updates the target
scope file (Scenario 1/2) checkboxes:

  - [x]  technique appears in plan (any tactic)
  - [ ]  not covered by any plan file (unchanged)
  - ~~[ ] technique~~  excluded from emulation (strikethrough)

Exact tactic match: removes <!-- plan tactic: ... --> comment.
Mismatch: keeps/adds comment showing which tactic(s) the plan uses.

Techniques in the plan that are absent from the scope file entirely are written
to <scope>_out_of_scope.csv.

Usage:
    python check.py --scope <Scenario.md> <plan1.md> [plan2.md ...]
    python check.py --scope <Scenario.md> --folder <plan_directory>
    python check.py --reset --scope <Scenario.md>

Options:
    --folder      Directory containing Phase*.md plan files. All matching files
                  are collected and sorted automatically.
    --exclude-alt Skip Reference Tables under headings containing [ALT] marker.
                  Use this to ignore alternative steps when checking coverage.
    --reset       Undo all marks in the scope file: revert [x] → [ ] and
                  strip <!-- plan tactic: ... --> annotations.
                  Skips strikethrough ~~techniques~~.

Examples:
    python check.py --scope "Scenario 1.md" Phase1.md Phase2.md
    python check.py --scope "Scenario 2.md" --folder ../Emulation_Plan/iis-path
    python check.py --scope "Scenario 1.md" --exclude-alt --folder ../Emulation_Plan/iis-path
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

def extract_plan_techniques(filepath: Path, exclude_alt: bool = False) -> list[tuple[str, str, str, str]]:
    """
    Return list of (norm_tactic, tech_id, tech_name, category) from all Reference Tables.
    category is the raw value of the "Category" column (e.g. "Calibrated - Not Benign").
    
    If exclude_alt is True, skip Reference Tables under headings containing [ALT] marker.
    """
    lines = filepath.read_text(encoding="utf-8").splitlines()
    results = []
    i = 0
    current_step_heading = ""  # Track the most recent ## heading
    
    while i < len(lines):
        # Track step headings (## level) to detect [ALT] sections
        step_match = re.match(r"^##\s+(.+)$", lines[i])
        if step_match:
            current_step_heading = step_match.group(1).strip()
        
        if re.match(r"#{1,4}\s+Reference\s+Tables", lines[i], re.IGNORECASE):
            # Skip this Reference Table if exclude_alt is True and current step contains [ALT]
            if exclude_alt and "[ALT]" in current_step_heading:
                i += 1
                # Skip until next non-table line
                while i < len(lines) and not _is_table_row(lines[i]):
                    i += 1
                while i < len(lines) and _is_table_row(lines[i]):
                    i += 1
                continue
            
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
    r"^(?P<indent>\s*)-\s+\[(?P<state>[ x])\]\s+(?:~~)?(?P<tid>T\d{4}(?:\.\d+)?)\b.*$"
)
SECTION_RE = re.compile(r"^(?P<hashes>#{1,4})\s+(?P<title>.+)$")
STRIKETHROUGH_RE = re.compile(r"~~.*?~~")  # Detect excluded techniques
PLAN_TACTIC_COMMENT_RE = re.compile(r"\s*<!--\s*plan tactic:[^>]*-->")


def collect_scope_pairs(scope_path: Path) -> set[tuple[str, str]]:
    """Return all (norm_tactic, tech_id) present in scope file.
    Excludes techniques marked with strikethrough ~~...~~."""
    lines = scope_path.read_text(encoding="utf-8").splitlines()
    pairs: set[tuple[str, str]] = set()
    cur = ""
    for line in lines:
        m = SECTION_RE.match(line.rstrip())
        if m and len(m.group("hashes")) >= 2:
            cur = _norm(m.group("title"))
        tm = TECH_LINE_RE.match(line.rstrip())
        if tm:
            # Skip techniques marked with strikethrough (excluded)
            if STRIKETHROUGH_RE.search(line):
                continue
            pairs.add((cur, tm.group("tid")))
    return pairs


def collect_scope_stats(scope_path: Path) -> dict[str, int]:
    """Return statistics about techniques in scope file.
    De-duplicates by technique ID (cross-tactic).
    Counts: total unique, marked [x], excluded ~~strike~~, pending [ ]."""
    lines = scope_path.read_text(encoding="utf-8").splitlines()
    all_tids: set[str] = set()
    marked_tids: set[str] = set()
    excluded_tids: set[str] = set()
    pending_tids: set[str] = set()
    for line in lines:
        tm = TECH_LINE_RE.match(line.rstrip())
        if tm:
            tid = tm.group("tid")
            state = tm.group("state")
            all_tids.add(tid)
            # Check for strikethrough (excluded)
            if STRIKETHROUGH_RE.search(line):
                excluded_tids.add(tid)
            elif state == "x":
                marked_tids.add(tid)
            elif state == " ":
                pending_tids.add(tid)
    return {
        "total_unique_techs": len(all_tids),
        "marked": len(marked_tids),
        "excluded": len(excluded_tids),
        "pending": len(pending_tids),
    }


# ---------------------------------------------------------------------------
# Core updater
# ---------------------------------------------------------------------------

def update_scope_file(
    scope_path: Path,
    covered: set[tuple[str, str]],
    covered_tids: dict[str, list[str]],
) -> tuple[int, int]:
    """
    Rewrite scope_path in-place.
      [x]  tech appears in plan (regardless of tactic match)
      [ ]  untouched
      ~~[ ] tech~~  excluded — never touched

    Returns (newly_marked, already_done).
    """
    lines = scope_path.read_text(encoding="utf-8").splitlines(keepends=True)
    cur_tactic  = ""
    n_marked    = 0
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

            # Skip techniques marked as strikethrough - never touch them
            if STRIKETHROUGH_RE.search(line):
                out.append(line)
                continue

            # If tech appears in plan (any tactic), mark as [x]
            if tid in covered_tids:
                key = (cur_tactic, tid)
                if key in covered:
                    # Exact match: [x] without comment
                    if state == " " or PLAN_TACTIC_COMMENT_RE.search(line):
                        if state == " ":
                            line = line.replace("- [ ]", "- [x]", 1)
                        line = PLAN_TACTIC_COMMENT_RE.sub("", line)
                        n_marked += 1
                    else:
                        n_already += 1
                else:
                    # Mismatch: [x] with comment showing plan tactics
                    plan_tacs = ", ".join(t.title() for t in covered_tids[tid])
                    if state == " ":
                        eol = "\n" if line.endswith("\n") else ""
                        line = (
                            line.rstrip("\n\r").replace("- [ ]", "- [x]", 1)
                            + f"  <!-- plan tactic: {plan_tacs} -->"
                            + eol
                        )
                        n_marked += 1
                    elif not PLAN_TACTIC_COMMENT_RE.search(line):
                        # Already [x] but missing comment - add it
                        eol = "\n" if line.endswith("\n") else ""
                        line = (
                            line.rstrip("\n\r")
                            + f"  <!-- plan tactic: {plan_tacs} -->"
                            + eol
                        )
                        n_already += 1
                    else:
                        n_already += 1

        out.append(line)

    scope_path.write_text("".join(out), encoding="utf-8")
    return n_marked, n_already


# ---------------------------------------------------------------------------
# Reset helper
# ---------------------------------------------------------------------------


def reset_scope_file(scope_path: Path) -> tuple[int, int]:
    """
    Revert all marks written by update_scope_file:
      [x] → [ ]   (also strips <!-- plan tactic: ... --> annotation)
    Skips excluded techniques (~~strikethrough~~).

    Returns (n_unchecked, n_cleared).
    """
    lines = scope_path.read_text(encoding="utf-8").splitlines(keepends=True)
    n_unchecked = 0
    n_cleared   = 0
    out = []

    for line in lines:
        tech_m = TECH_LINE_RE.match(line.rstrip("\n\r"))
        if tech_m:
            state = tech_m.group("state")
            # Skip excluded techniques (strikethrough)
            if STRIKETHROUGH_RE.search(line):
                out.append(line)
                continue
            if state == "x":
                # Reset [x] to [ ] and strip any comment
                line = line.replace("- [x]", "- [ ]", 1)
                stripped = line.rstrip("\n\r")
                eol = line[len(stripped):]  # preserve original line ending
                line = PLAN_TACTIC_COMMENT_RE.sub("", stripped).rstrip() + eol
                n_unchecked += 1
        out.append(line)

    scope_path.write_text("".join(out), encoding="utf-8")
    return n_unchecked, n_cleared


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
    
    exclude_alt = "--exclude-alt" in args
    args = [a for a in args if a != "--exclude-alt"]

    idx = args.index("--scope")
    if idx + 1 >= len(args):
        print("[!] --scope requires a filename argument.", file=sys.stderr)
        sys.exit(1)

    scope_file = Path(args[idx + 1])

    # Collect plan files from --folder and/or positional arguments
    consumed = {"--scope", args[idx + 1]}
    folder_path = None
    if "--folder" in args:
        fi = args.index("--folder")
        if fi + 1 >= len(args):
            print("[!] --folder requires a directory argument.", file=sys.stderr)
            sys.exit(1)
        folder_path = Path(args[fi + 1])
        consumed.update({"--folder", args[fi + 1]})

    plan_files = [Path(a) for a in args if a not in consumed]

    if folder_path is not None:
        if not folder_path.is_dir():
            print(f"[!] Folder not found: {folder_path}", file=sys.stderr)
            sys.exit(1)
        phase_files = sorted(folder_path.rglob("Phase*.md"))
        if not phase_files:
            print(f"[!] No Phase*.md files found in {folder_path}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Folder {folder_path}: found {len(phase_files)} Phase*.md file(s)")
        plan_files = phase_files + plan_files

    if not scope_file.exists():
        print(f"[!] Scope file not found: {scope_file}", file=sys.stderr)
        sys.exit(1)

    # ── reset mode ──────────────────────────────────────────────────────────
    if reset_mode:
        n_unchk, _ = reset_scope_file(scope_file)
        print(f"[+] Reset {scope_file.name}")
        print(f"    [ ] Unchecked [x]   : {n_unchk}")
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

    if exclude_alt:
        print("[*] --exclude-alt enabled: skipping Reference Tables under [ALT] headings")

    # Parse all plan files
    covered: set[tuple[str, str]]          = set()
    covered_tids: dict[str, list[str]]     = defaultdict(list)
    name_map: dict[str, str]               = {}
    total_calibrated   = 0
    total_uncalibrated = 0
    total_unknown_cat  = 0

    for p in plan_files:
        rows = extract_plan_techniques(p, exclude_alt=exclude_alt)
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

    # Collect scope pairs first to check if parent exists before adding
    scope_pairs = collect_scope_pairs(scope_file)

    # Second pass: add parent techniques only if parent exists in scope
    for p in plan_files:
        rows = extract_plan_techniques(p, exclude_alt=exclude_alt)
        for tac, tid, name, cat in rows:
            # If subtechnique (TXXXX.YYY), also tick parent technique (TXXXX) if it exists in scope
            parent_match = re.match(r"(T\d{4})\.\d{3}", tid)
            if parent_match:
                parent_tid = parent_match.group(1)
                parent_key = (tac, parent_tid)
                if parent_key in scope_pairs:
                    covered.add(parent_key)
                    if tac not in covered_tids[parent_tid]:
                        covered_tids[parent_tid].append(tac)
                    if parent_tid not in name_map and name:
                        # Use parent name by stripping subtechnique part
                        parent_name = re.sub(r":\s+[^:]+$", "", name)
                        name_map[parent_tid] = parent_name

    total_pairs = len(covered)
    print(f"[*] Total unique (tactic, tech) pairs: {total_pairs}")
    unk_str = f", Unknown: {total_unknown_cat}" if total_unknown_cat else ""
    print(f"[*] Calibrated: {total_calibrated}, Not Calibrated: {total_uncalibrated}{unk_str}")

    # Find plan techniques absent from scope entirely
    out_of_scope = covered - scope_pairs

    # Update scope file
    n_marked, n_already = update_scope_file(scope_file, covered, covered_tids)

    # Collect scope statistics
    scope_stats = collect_scope_stats(scope_file)

    print(f"\n[+] {scope_file.name}")
    print(f"    [x] Newly marked         : {n_marked}")
    print(f"    Already done             : {n_already}")
    print(f"    Not in scope at all      : {len(out_of_scope)}")
    print(f"\n[*] Scope Statistics (de-dup by technique ID):")
    print(f"    Total techniques         : {scope_stats['total_unique_techs']}")
    print(f"    Done ([x])               : {scope_stats['marked']}")
    print(f"    Excluded (~~strike~~)    : {scope_stats['excluded']}")
    print(f"    Pending ([ ])            : {scope_stats['pending']}")

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
