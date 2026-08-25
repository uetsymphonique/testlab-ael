#!/usr/bin/env python3
"""
export_atomic_cases.py — Export Atomic Red Team test cases for techniques in a scope file.

Reads a technique scope Markdown file (same format as Scenario 1/2 or
prevent-technique-list.md), then looks up each technique's atomic tests in
atomic-red-team/atomics/<TID>/<TID>.yaml and writes one CSV row per atomic test.

Rows are grouped by scope order: tactic section → technique → atomic tests.

Usage:
    python export_atomic_cases.py <scope.md>
    python export_atomic_cases.py ../q3-plan/statistics/prevent-technique-list.md --out cases.csv
    python export_atomic_cases.py <scope.md> --platform windows
    python export_atomic_cases.py <scope.md> --out -            # CSV to stdout

Options:
    --atomics-dir   Path to atomic-red-team/atomics directory.
                    Default: <repo-root>/atomic-red-team/atomics
    --out           Output CSV path. Default: <scope>_atomic_cases.csv beside
                    the scope file. Use "-" for stdout.
    --platform      Only include tests whose supported_platforms contains this
                    platform (case-insensitive). Default: windows.
                    Use --all-platforms to keep every test.
    --all-platforms Disable platform filtering.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

import yaml

DEFAULT_ATOMICS_DIR = (
    Path(__file__).resolve().parent.parent.parent / "atomic-red-team" / "atomics"
)

OUTPUT_HEADERS = [
    "Tactic",
    "Technique ID",
    "Technique Name",
    "Atomic Test Name",
    "Test GUID",
    "Supported Platforms",
    "Executor",
    "Elevation Required",
    "Input Arguments",
    "Dependencies",
    "Description",
]

TECH_LINE_RE = re.compile(
    r"^\s*-\s+\[(?P<state>[ x])\]\s+(?:~~)?(?P<tid>T\d{4}(?:\.\d+)?)\b\s*-?\s*(?P<name>.*)$"
)
SECTION_RE = re.compile(r"^(?P<hashes>#{1,4})\s+(?P<title>.+)$")
STRIKETHROUGH_RE = re.compile(r"~~.*?~~")


# ---------------------------------------------------------------------------
# Scope file parsing (mirrors check.py)
# ---------------------------------------------------------------------------

def parse_scope(scope_path: Path) -> list[dict]:
    """
    Parse a scope Markdown file into ordered technique rows:
    [{"tactic": ..., "tid": ..., "name": ...}, ...]
    Deduplicated by technique ID, keeping first occurrence (first tactic).
    Skips excluded techniques (~~strikethrough~~).
    """
    lines = scope_path.read_text(encoding="utf-8").splitlines()
    rows: list[dict] = []
    seen: set[str] = set()
    cur_tactic = ""

    for line in lines:
        sec = SECTION_RE.match(line.rstrip())
        if sec and len(sec.group("hashes")) >= 2:
            cur_tactic = sec.group("title").strip()

        m = TECH_LINE_RE.match(line.rstrip("\n\r"))
        if m:
            if STRIKETHROUGH_RE.search(line):
                continue
            tid = m.group("tid").strip()
            if tid in seen:
                continue
            seen.add(tid)
            rows.append(
                {
                    "tactic": cur_tactic,
                    "tid": tid,
                    "name": m.group("name").strip(),
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Atomics parsing
# ---------------------------------------------------------------------------

def load_technique_yaml(atomics_dir: Path, tid: str):
    """Load atomics/<TID>/<TID>.yaml. Returns parsed dict or None."""
    yaml_path = atomics_dir / tid / f"{tid}.yaml"
    if not yaml_path.exists():
        return None
    with yaml_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def format_input_arguments(test: dict) -> str:
    """Render input_arguments as 'name=default' joined by '; '."""
    args = test.get("input_arguments") or {}
    parts = []
    for name, spec in args.items():
        default = str((spec or {}).get("default", "")).replace("\n", " ").strip()
        parts.append(f"{name}={default}")
    return "; ".join(parts)


def format_dependencies(test: dict) -> str:
    """Count dependencies; return '0' or 'N (desc1 / desc2 / ...)'."""
    deps = test.get("dependencies") or []
    if not deps:
        return "0"
    descs = []
    for d in deps:
        desc = " ".join(str(d.get("description", "")).split())
        descs.append(desc)
    return f"{len(deps)} ({' / '.join(descs)})"


def build_rows(
    scope_rows: list[dict],
    atomics_dir: Path,
    platform: str | None,
) -> tuple[list[dict], list[str]]:
    """
    Build one output row per atomic test. Returns (rows, missing_tids).
    Techniques without a YAML file are reported as missing.
    """
    out_rows: list[dict] = []
    missing_tids: list[str] = []

    for tech in scope_rows:
        tid = tech["tid"]
        data = load_technique_yaml(atomics_dir, tid)
        if data is None:
            missing_tids.append(tid)
            continue

        display_name = str(data.get("display_name", "")) or tech["name"]
        tests = data.get("atomic_tests") or []

        matched = 0
        for test in tests:
            platforms = [str(p).lower() for p in (test.get("supported_platforms") or [])]
            if platform is not None and platform.lower() not in platforms:
                continue
            matched += 1

            executor = test.get("executor") or {}
            elevation = executor.get("elevation_required")
            elevation_str = ""
            if elevation is not None:
                elevation_str = "true" if elevation else "false"

            desc = " ".join(str(test.get("description", "")).split())

            out_rows.append(
                {
                    "Tactic": tech["tactic"],
                    "Technique ID": tid,
                    "Technique Name": display_name,
                    "Atomic Test Name": str(test.get("name", "")).strip(),
                    "Test GUID": str(test.get("auto_generated_guid", "")).strip(),
                    "Supported Platforms": ", ".join(
                        str(p) for p in (test.get("supported_platforms") or [])
                    ),
                    "Executor": str(executor.get("name", "")).strip(),
                    "Elevation Required": elevation_str,
                    "Input Arguments": format_input_arguments(test),
                    "Dependencies": format_dependencies(test),
                    "Description": desc,
                }
            )

        if not tests:
            print(f"[-] No atomic tests defined: {tid}", file=sys.stderr)
        elif matched == 0 and platform is not None:
            print(f"[-] No [{platform}] atomic tests: {tid}", file=sys.stderr)

    return out_rows, missing_tids


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(out_path: Path | None, rows: list[dict]) -> None:
    if out_path == Path("-"):
        writer = csv.DictWriter(sys.stdout, fieldnames=OUTPUT_HEADERS)
        writer.writeheader()
        writer.writerows(rows)
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_HEADERS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Wrote {len(rows)} row(s) to {out_path}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export Atomic Red Team test cases to CSV for techniques listed "
            "in a scope Markdown file."
        )
    )
    parser.add_argument("scope", type=Path, help="Technique scope Markdown file.")
    parser.add_argument(
        "--atomics-dir",
        type=Path,
        default=DEFAULT_ATOMICS_DIR,
        help=f"Path to atomic-red-team/atomics directory. Default: {DEFAULT_ATOMICS_DIR}",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=(
            "Output CSV path. Default: <scope>_atomic_cases.csv beside the "
            "scope file. Use '-' for stdout."
        ),
    )
    parser.add_argument(
        "--platform",
        default="windows",
        help="Filter tests by supported platform. Default: windows.",
    )
    parser.add_argument(
        "--all-platforms",
        action="store_true",
        default=False,
        help="Include every atomic test regardless of platform.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.scope.exists():
        print(f"[!] Scope file not found: {args.scope}", file=sys.stderr)
        return 1
    if not args.atomics_dir.is_dir():
        print(f"[!] Atomics directory not found: {args.atomics_dir}", file=sys.stderr)
        return 1

    scope_rows = parse_scope(args.scope)
    if not scope_rows:
        print("[!] No techniques found in scope file.", file=sys.stderr)
        return 1
    print(
        f"[*] {args.scope.name}: {len(scope_rows)} unique technique(s)",
        file=sys.stderr,
    )

    platform = None if args.all_platforms else args.platform
    if platform is None:
        print("[*] Platform filter disabled (--all-platforms)", file=sys.stderr)

    rows, missing_tids = build_rows(scope_rows, args.atomics_dir, platform)

    for tid in missing_tids:
        print(f"[!] No atomic tests file found: {tid}", file=sys.stderr)

    per_tech: dict[str, int] = {}
    for r in rows:
        per_tech[r["Technique ID"]] = per_tech.get(r["Technique ID"], 0) + 1
    print(
        f"[+] {len(rows)} atomic test(s) across {len(per_tech)}/{len(scope_rows)} technique(s)",
        file=sys.stderr,
    )

    out_path = args.out
    if out_path is None:
        out_path = args.scope.with_name(args.scope.stem + "_atomic_cases.csv")

    write_csv(out_path, rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
