"""Command-line interface for LogShield."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .redactor import redact_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logshield",
        description="Redact common secrets and email addresses from logs locally.",
    )
    parser.add_argument("input", nargs="?", help="Input log file. Omit to read from stdin.")
    parser.add_argument("-o", "--output", help="Write redacted output to this file. Default: stdout.")
    parser.add_argument("--in-place", action="store_true", help="Replace the input file (creates a .bak backup).")
    parser.add_argument("--summary", action="store_true", help="Print replacement counts to stderr.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.in_place and not args.input:
        parser.error("--in-place requires an input file")
    if args.in_place and args.output:
        parser.error("Use either --in-place or --output, not both")

    try:
        if args.input:
            source = Path(args.input)
            original = source.read_text(encoding="utf-8", errors="replace")
        else:
            original = sys.stdin.read()

        cleaned, counts = redact_text(original)

        if args.in_place:
            source.with_suffix(source.suffix + ".bak").write_text(original, encoding="utf-8")
            source.write_text(cleaned, encoding="utf-8")
        elif args.output:
            Path(args.output).write_text(cleaned, encoding="utf-8")
        else:
            sys.stdout.write(cleaned)

        if args.summary:
            total = sum(counts.values())
            print(f"LogShield: redacted {total} item(s).", file=sys.stderr)
            for name, count in sorted(counts.items()):
                print(f"  {name}: {count}", file=sys.stderr)

        return 0
    except OSError as exc:
        print(f"logshield: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
