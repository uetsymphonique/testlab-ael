#!/usr/bin/env python3
"""Flush the criteria/category columns of Reference Tables in Phase files.

Clears the `Detection Criteria`, `Category`, and `Calibration Reason` cells of
every Reference Table row back to a placeholder (default ``TBD``) so the
`write-detection-criteria` and `assign-category` skills can be re-run from a
clean evidence base. All other columns are left untouched.

Only markdown tables that actually contain at least one of the target columns
are modified, so non-Reference tables in the same file are safe.

Usage:
    python flush_table.py <file-or-dir> [<file-or-dir> ...]
    python flush_table.py path/to/"Phase 1.md"
    python flush_table.py path/to/some-path/          # recurses for *.md
    python flush_table.py --dry-run path/to/dir/
    python flush_table.py --columns "Detection Criteria,Category" file.md
    python flush_table.py --placeholder "" file.md
    python flush_table.py --step "lateral movement" file.md   # keyword search + confirm
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_COLUMNS = ["Detection Criteria", "Category", "Calibration Reason"]
DEFAULT_PLACEHOLDER = "TBD"

# A markdown table separator row: only |, -, :, and whitespace, with >=1 dash.
# Trailing | is optional — some editors omit it.
SEP_RE = re.compile(r"^\s*\|[\s:|-]*-[\s:|-]*\|?\s*$")
# Split a table row on unescaped pipes.
PIPE_RE = re.compile(r"(?<!\\)\|")
# Markdown heading: capture level and text.
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)")


def split_cells(line: str) -> list[str] | None:
    """Return the inner cells of a markdown table row, or None if not a row."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return None
    parts = PIPE_RE.split(line.rstrip("\n"))
    # parts[0] is before the first pipe.
    # If the row ends with |, parts[-1] is empty — drop it.
    # If the row has no trailing |, parts[-1] is the last cell — keep it.
    if len(parts) < 3:
        return None
    return parts[1:-1] if parts[-1].strip() == "" else parts[1:]


def find_sections(lines: list[str], keyword: str) -> list[tuple[int, int, str]]:
    """Return list of (start_line, end_line_exclusive, heading_text) matching keyword.

    A section runs from its heading line up to (but not including) the next
    heading of the same or higher level (fewer #s), or end of file.
    """
    keyword_lower = keyword.lower()
    matches: list[tuple[int, int, str]] = []

    # Collect all headings first.
    headings: list[tuple[int, int, str]] = []  # (line_idx, level, text)
    for idx, line in enumerate(lines):
        m = HEADING_RE.match(line)
        if m:
            headings.append((idx, len(m.group(1)), m.group(2).strip()))

    for i, (idx, level, text) in enumerate(headings):
        if keyword_lower not in text.lower():
            continue
        # Find the end: next heading with level <= current level.
        end = len(lines)
        for j in range(i + 1, len(headings)):
            if headings[j][1] <= level:
                end = headings[j][0]
                break
        matches.append((idx, end, text))

    return matches


def flush_text(
    text: str,
    target_cols: list[str],
    placeholder: str,
    line_range: tuple[int, int] | None = None,
) -> tuple[str, int, int]:
    """Return (new_text, tables_flushed, rows_flushed).

    If line_range is given as (start, end), only tables whose header line falls
    within [start, end) are flushed.
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    tables = 0
    rows = 0
    targets_lower = [c.lower() for c in target_cols]

    while i < len(lines):
        header_cells = split_cells(lines[i])
        is_header = (
            header_cells is not None
            and i + 1 < len(lines)
            and SEP_RE.match(lines[i + 1])
        )
        if not is_header:
            out.append(lines[i])
            i += 1
            continue

        in_range = line_range is None or (line_range[0] <= i < line_range[1])

        # Map target column name -> index in this table.
        header_names = [c.strip().lower() for c in header_cells]
        col_idx = {
            t: header_names.index(t)
            for t in targets_lower
            if t in header_names
        }
        if not col_idx or not in_range:
            # Not a Reference Table or outside target section — leave untouched.
            out.append(lines[i])
            i += 1
            continue

        tables += 1
        out.append(lines[i])          # header
        out.append(lines[i + 1])      # separator
        j = i + 2
        while j < len(lines):
            cells = split_cells(lines[j])
            if cells is None:
                break
            changed = False
            for idx in col_idx.values():
                if idx < len(cells):
                    cells[idx] = f" {placeholder} " if placeholder else "  "
                    changed = True
            if changed:
                rows += 1
            out.append("|" + "|".join(cells) + "|")
            j += 1
        i = j

    return "\n".join(out), tables, rows


def confirm_section(heading: str, start: int, end: int) -> bool:
    """Ask the user whether the matched section is correct. Return True to proceed."""
    print(f"\n  Found: \"{heading}\"  (lines {start + 1}–{end})")
    while True:
        ans = input("  Flush this section? [y/n] ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please enter y or n.")


def iter_md_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.rglob("*.md")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"warning: not found: {p}", file=sys.stderr)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Phase .md files or directories (recursed for *.md)")
    ap.add_argument("--columns", default=",".join(DEFAULT_COLUMNS),
                    help="comma-separated column headers to flush "
                         f"(default: {','.join(DEFAULT_COLUMNS)})")
    ap.add_argument("--placeholder", default=DEFAULT_PLACEHOLDER,
                    help=f"value to write into flushed cells (default: {DEFAULT_PLACEHOLDER!r})")
    ap.add_argument("--dry-run", action="store_true", help="report changes without writing")
    ap.add_argument("--step", metavar="KEYWORD",
                    help="keyword to search headings; only flush tables inside the "
                         "matched section (interactive confirmation required)")
    args = ap.parse_args()

    target_cols = [c.strip() for c in args.columns.split(",") if c.strip()]
    files = iter_md_files(args.paths)
    if not files:
        print("no files to process", file=sys.stderr)
        return 1

    total_rows = 0
    touched_files = 0
    for f in files:
        original = f.read_text(encoding="utf-8")
        lines = original.split("\n")

        line_range: tuple[int, int] | None = None

        if args.step:
            sections = find_sections(lines, args.step)
            if not sections:
                print(f"{f}: no heading matching \"{args.step}\" — skipped")
                continue
            if len(sections) > 1:
                print(f"{f}: {len(sections)} headings match \"{args.step}\":")
                for start, end, heading in sections:
                    print(f"  [{start + 1}] {heading}")
                print("  Disambiguate with a more specific keyword.")
                continue
            start, end, heading = sections[0]
            if not confirm_section(heading, start, end):
                print(f"  Skipped.")
                continue
            line_range = (start, end)

        new_text, tables, rows = flush_text(original, target_cols, args.placeholder, line_range)
        if rows and new_text != original:
            touched_files += 1
            total_rows += rows
            tag = "[dry-run] " if args.dry_run else ""
            scope = f" in section \"{args.step}\"" if args.step else ""
            print(f"{tag}{f}: flushed {rows} row(s) across {tables} table(s){scope}")
            if not args.dry_run:
                f.write_text(new_text, encoding="utf-8")
        elif args.step:
            print(f"{f}: section found but no target-column rows to flush")

    verb = "would flush" if args.dry_run else "flushed"
    print(f"\n{verb} {total_rows} row(s) in {touched_files} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
