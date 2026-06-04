#!/usr/bin/env python3

import argparse
import csv
import re
import sys
from pathlib import Path


CANONICAL_HEADERS = [
    "Tactic",
    "Technique ID",
    "Technique Name",
    "Platform",
    "Detection Criteria",
    "Category",
    "Calibration Reason",
    "Red Team Activity",
    "Hosts",
    "Users",
]

INPUT_HEADERS = [
    *CANONICAL_HEADERS,
    "Source Code Links",
    "Relevant CTI Reports",
]

FILTERS = {"not-benign", "benign", "calibrated", "not-calibrated"}

OUTPUT_HEADERS = ["Step"] + CANONICAL_HEADERS


def split_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("||"):
        s = s[2:]
    elif s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]

    cells = []
    cur = []
    escaped = False
    for ch in s:
        if ch == "|" and not escaped:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        escaped = ch == "\\" and not escaped
        if ch != "\\":
            escaped = False
    cells.append("".join(cur).strip())
    return cells


def is_separator(line: str) -> bool:
    s = line.strip().lstrip("|")
    return bool(re.fullmatch(r"[\s\-:|]+", s))


def is_table_row(line: str) -> bool:
    s = line.strip()
    return s.startswith("|") or s.startswith("||")


def normalize_header(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def canonical_header(value: str) -> str:
    normalized = normalize_header(value)
    for header in INPUT_HEADERS:
        if normalized == normalize_header(header):
            return header
    return value.strip()


def is_reference_tables_heading(line: str) -> bool:
    return bool(re.match(r"#{1,6}\s+Reference\s+Tables\s*$", line.strip(), re.IGNORECASE))


def is_next_heading(line: str) -> bool:
    return bool(re.match(r"#{1,6}\s+", line.strip()))


def extract_reference_rows(filepath: Path, exclude_alt: bool = False) -> list[dict[str, str]]:
    lines = filepath.read_text(encoding="utf-8").splitlines()
    rows = []
    i = 0
    current_step_heading = ""

    while i < len(lines):
        step_match = re.match(r"^##\s+(.+)$", lines[i])
        if step_match:
            current_step_heading = step_match.group(1).strip()

        if not is_reference_tables_heading(lines[i]):
            i += 1
            continue

        if exclude_alt and "[ALT]" in current_step_heading:
            i += 1
            while i < len(lines) and not is_table_row(lines[i]):
                i += 1
            while i < len(lines) and is_table_row(lines[i]):
                i += 1
            continue

        i += 1
        while i < len(lines) and not is_table_row(lines[i]):
            if is_next_heading(lines[i]):
                break
            i += 1

        if i >= len(lines) or not is_table_row(lines[i]):
            continue

        headers = [canonical_header(h) for h in split_row(lines[i])]
        i += 1

        if i < len(lines) and is_table_row(lines[i]) and is_separator(lines[i]):
            i += 1

        while i < len(lines) and is_table_row(lines[i]):
            cells = split_row(lines[i])
            while len(cells) < len(headers):
                cells.append("")

            row = {header: cells[idx] if idx < len(cells) else "" for idx, header in enumerate(headers)}
            if any(row.values()):
                row = {header: row.get(header, "") for header in CANONICAL_HEADERS}
                row["Step"] = current_step_heading
                rows.append(row)
            i += 1

    return rows


def category_matches(category: str, filters: set[str]) -> bool:
    if not filters:
        return True

    normalized = category.strip().lower()
    is_not_calibrated = normalized.startswith("not calibrated")
    is_calibrated = normalized.startswith("calibrated")
    is_not_benign = "not benign" in normalized
    is_benign = "benign" in normalized and not is_not_benign

    return any(
        (
            (flt == "not-benign" and is_not_benign)
            or (flt == "benign" and is_benign)
            or (flt == "calibrated" and is_calibrated)
            or (flt == "not-calibrated" and is_not_calibrated)
        )
        for flt in filters
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Reference Tables from one or more emulation plan Markdown files to CSV."
    )
    parser.add_argument("plans", nargs="*", type=Path, help="Plan Markdown file(s) to parse.")
    parser.add_argument("--file", type=Path, help="Single plan Markdown file to parse.")
    parser.add_argument("--folder", type=Path, help="Directory containing Phase*.md plan files.")
    parser.add_argument("--out", type=Path, help="CSV output path. Defaults to stdout.")
    parser.add_argument(
        "--filter",
        nargs="+",
        choices=sorted(FILTERS),
        default=[],
        help="Category filter(s): not-benign, benign, calibrated, not-calibrated.",
    )
    parser.add_argument(
        "--exclude-alt",
        action="store_true",
        default=False,
        help="Skip Reference Tables under headings containing [ALT] marker.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    plan_files = list(args.plans)

    if args.file is not None:
        plan_files = [args.file] + plan_files

    if args.folder is not None:
        if not args.folder.is_dir():
            print(f"[!] Folder not found: {args.folder}", file=sys.stderr)
            return 1
        phase_files = sorted(args.folder.rglob("Phase*.md"))
        if not phase_files:
            print(f"[!] No Phase*.md files found in {args.folder}", file=sys.stderr)
            return 1
        print(f"[*] Folder {args.folder}: found {len(phase_files)} Phase*.md file(s)", file=sys.stderr)
        plan_files = phase_files + plan_files

    if not plan_files:
        print("[!] No plan files specified. Provide at least one plan .md file, use --file, or use --folder.", file=sys.stderr)
        return 1

    missing = [path for path in plan_files if not path.exists()]
    if missing:
        for path in missing:
            print(f"[!] Plan file not found: {path}", file=sys.stderr)
        return 1

    if args.exclude_alt:
        print("[*] --exclude-alt enabled: skipping Reference Tables under [ALT] headings", file=sys.stderr)

    rows = []
    filters = set(args.filter)
    for path in plan_files:
        extracted = extract_reference_rows(path, exclude_alt=args.exclude_alt)
        rows.extend(row for row in extracted if category_matches(row.get("Category", ""), filters))

    fieldnames = OUTPUT_HEADERS

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] Wrote {len(rows)} row(s) to {args.out}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
