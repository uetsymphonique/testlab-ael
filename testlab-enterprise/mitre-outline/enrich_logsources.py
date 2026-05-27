#!/usr/bin/env python3
"""
enrich_logsources.py — Enrich a plan CSV with log sources from mitre-knowledge-base/techniques.

Reads a CSV produced by export_ref_tables.py or assign-acw (same core columns, ACW column optional).
For each unique Technique ID in the CSV, looks up detection entries for the specified platform
in the MITRE knowledge-base technique files, then outputs one row per log source entry.

Usage:
    python enrich_logsources.py plan.csv [--platform windows] [--techniques-dir PATH] [--out out.csv]
"""

import argparse
import csv
import re
import sys
from pathlib import Path

DEFAULT_TECHNIQUES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "mitre-knowledge-base" / "techniques"
)
DEFAULT_PLATFORM = "windows"

ENRICH_HEADERS = [
    "Detection ID",
    "Detection Description",
    "Log Source",
    "Event Filter",
    "Data Component",
]
EMPTY_ENRICH = {h: "" for h in ENRICH_HEADERS}

_TECHNIQUE_HEADER_RE = re.compile(r"^### (T[\d.]+)\s*-\s*(.+)")
_DETECTION_ENTRY_RE = re.compile(r"^- \[(AN\d+)\] \*\*\[([^\]]+)\]\*\* (.+)")
_LOG_SOURCE_LINE_RE = re.compile(r"^\s+- \*\*Log sources:\*\* (.+)")
_LOG_SOURCE_ENTRY_RE = re.compile(r"`([^`]+)`\s*\(([^)]*)\)\s*\[([^\]]+)\]")


def read_csv_rows(csv_path: Path) -> tuple[list[str], list[dict]]:
    """Return (fieldnames, rows) from the plan CSV."""
    with csv_path.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    return fieldnames, rows


def parse_log_source_string(log_source_str: str) -> list[tuple[str, str, str]]:
    """Parse a log sources string into (source, event_filter, data_component) tuples."""
    return _LOG_SOURCE_ENTRY_RE.findall(log_source_str)


def extract_from_file(
    content: str,
    target_tids: set[str],
    platform_lower: str,
    seen_det_ids: set[tuple[str, str]],
) -> dict[str, list[dict]]:
    """
    Extract enrichment entries per technique ID from a tactic markdown file.
    Returns {tid: [enrich_dict, ...]} where each enrich_dict has ENRICH_HEADERS keys.
    `seen_det_ids` is mutated to deduplicate (tid, det_id) across tactic files.
    """
    lines = content.splitlines()
    results: dict[str, list[dict]] = {}

    current_tid: str | None = None
    in_detection = False
    pending_detection: tuple[str, str, str] | None = None  # (det_id, platform_label, desc)

    for line in lines:
        # ── Technique header ────────────────────────────────────────────────
        m = _TECHNIQUE_HEADER_RE.match(line)
        if m:
            current_tid = m.group(1).strip()
            in_detection = False
            pending_detection = None
            if current_tid not in target_tids:
                current_tid = None
            continue

        if current_tid is None:
            continue

        stripped = line.strip()

        # ── Section boundaries ───────────────────────────────────────────────
        if stripped == "**Detection**":
            in_detection = True
            continue

        if stripped == "**Procedure Examples**":
            in_detection = False
            pending_detection = None
            continue

        if not in_detection:
            continue

        # ── Detection entry bullet ───────────────────────────────────────────
        m = _DETECTION_ENTRY_RE.match(line)
        if m:
            pending_detection = (m.group(1), m.group(2), m.group(3).strip())
            continue

        # ── Log sources sub-bullet ────────────────────────────────────────────
        m = _LOG_SOURCE_LINE_RE.match(line)
        if m and pending_detection:
            det_id, det_platform_label, det_desc = pending_detection
            pending_detection = None

            if det_platform_label.lower() != platform_lower:
                continue

            dedup_key = (current_tid, det_id)
            if dedup_key in seen_det_ids:
                continue
            seen_det_ids.add(dedup_key)

            log_sources = parse_log_source_string(m.group(1))
            entries = results.setdefault(current_tid, [])

            if log_sources:
                for source, event_filter, data_component in log_sources:
                    entries.append(
                        {
                            "Detection ID": det_id,
                            "Detection Description": det_desc,
                            "Log Source": source,
                            "Event Filter": event_filter,
                            "Data Component": data_component,
                        }
                    )
            else:
                entries.append(
                    {
                        "Detection ID": det_id,
                        "Detection Description": det_desc,
                        "Log Source": "",
                        "Event Filter": "",
                        "Data Component": "",
                    }
                )

    return results


def lookup_logsources(
    techniques_dir: Path,
    target_tids: set[str],
    platform: str,
) -> tuple[dict[str, list[dict]], set[str], set[str]]:
    """
    Returns (enrich_map, tids_not_in_kb, tids_no_platform_coverage).

    - enrich_map: {tid: [enrich_dict, ...]} — one entry per log source
    - tids_not_in_kb: technique IDs not found in any techniques file
    - tids_no_platform_coverage: found in KB but no detection entry for the requested platform
    """
    platform_lower = platform.lower()

    tids_in_kb: set[str] = set()
    enrich_map: dict[str, list[dict]] = {}
    seen_det_ids: set[tuple[str, str]] = set()

    for tactic_file in sorted(techniques_dir.glob("*.md")):
        content = tactic_file.read_text(encoding="utf-8")

        for m in re.finditer(r"^### (T[\d.]+)\s*-", content, re.MULTILINE):
            if m.group(1) in target_tids:
                tids_in_kb.add(m.group(1))

        file_map = extract_from_file(content, target_tids, platform_lower, seen_det_ids)
        for tid, entries in file_map.items():
            enrich_map.setdefault(tid, []).extend(entries)

    tids_not_in_kb = target_tids - tids_in_kb
    tids_no_platform_coverage = tids_in_kb - enrich_map.keys()

    return enrich_map, tids_not_in_kb, tids_no_platform_coverage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Enrich a plan CSV (from export_ref_tables.py or assign-acw) with log sources "
            "from mitre-knowledge-base/techniques for a given platform."
        )
    )
    parser.add_argument("csv_file", type=Path, help="Input plan CSV file.")
    parser.add_argument(
        "--platform",
        default=DEFAULT_PLATFORM,
        help=f"Detection platform label to filter on (case-insensitive). Default: {DEFAULT_PLATFORM}",
    )
    parser.add_argument(
        "--techniques-dir",
        type=Path,
        default=DEFAULT_TECHNIQUES_DIR,
        help=f"Path to mitre-knowledge-base/techniques directory. Default: {DEFAULT_TECHNIQUES_DIR}",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output CSV path. Defaults to stdout.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.csv_file.exists():
        print(f"[!] CSV file not found: {args.csv_file}", file=sys.stderr)
        return 1

    if not args.techniques_dir.is_dir():
        print(f"[!] Techniques directory not found: {args.techniques_dir}", file=sys.stderr)
        return 1

    input_fieldnames, input_rows = read_csv_rows(args.csv_file)
    if not input_rows:
        print("[!] No rows found in input CSV.", file=sys.stderr)
        return 1

    target_tids = {r.get("Technique ID", "").strip() for r in input_rows} - {""}
    print(
        f"[*] {len(target_tids)} unique technique(s) in plan CSV, platform filter: [{args.platform}]",
        file=sys.stderr,
    )

    enrich_map, not_in_kb, no_coverage = lookup_logsources(
        args.techniques_dir, target_tids, args.platform
    )

    if not_in_kb:
        for tid in sorted(not_in_kb):
            print(f"[!] Not found in knowledge base: {tid}", file=sys.stderr)

    if no_coverage:
        for tid in sorted(no_coverage):
            print(f"[-] No [{args.platform}] detection entry: {tid}", file=sys.stderr)

    output_fieldnames = input_fieldnames + ENRICH_HEADERS

    out_rows: list[dict] = []
    for row in input_rows:
        tid = row.get("Technique ID", "").strip()
        enrichments = enrich_map.get(tid, [])
        if enrichments:
            for enrich in enrichments:
                out_rows.append({**row, **enrich})
        else:
            out_rows.append({**row, **EMPTY_ENRICH})

    total_enrich = sum(len(v) for v in enrich_map.values())
    print(
        f"[+] {len(out_rows)} output row(s) ({total_enrich} log source entries across {len(enrich_map)} technique(s))",
        file=sys.stderr,
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=output_fieldnames)
            writer.writeheader()
            writer.writerows(out_rows)
        print(f"[+] Wrote {len(out_rows)} row(s) to {args.out}", file=sys.stderr)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=output_fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
