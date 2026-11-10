"""Command-line interface for LogShield."""
from __future__ import annotations
import argparse, sys
from pathlib import Path
from .redactor import load_custom_rules, redact_json_text, redact_text, RULES

def build_parser() -> argparse.ArgumentParser:
    parser=argparse.ArgumentParser(prog="logshield", description="Redact common secrets and personal data from logs locally.")
    parser.add_argument("input", nargs="?", help="Input file; omit to read stdin.")
    parser.add_argument("-o","--output", help="Write cleaned output to a file.")
    parser.add_argument("--in-place", action="store_true", help="Replace input file after creating a .bak backup.")
    parser.add_argument("--json", action="store_true", help="Parse valid JSON and redact values while preserving structure.")
    parser.add_argument("--rules", help="Optional JSON file containing custom regex rules.")
    parser.add_argument("--summary", action="store_true", help="Print redaction counts to stderr.")
    return parser

def main() -> int:
    parser=build_parser(); args=parser.parse_args()
    if args.in_place and not args.input: parser.error("--in-place requires an input file")
    if args.in_place and args.output: parser.error("Use either --in-place or --output, not both")
    try:
        source=Path(args.input) if args.input else None
        original=source.read_text(encoding="utf-8", errors="replace") if source else sys.stdin.read()
        custom=load_custom_rules(args.rules)
        if args.json:
            cleaned,counts=redact_json_text(original, custom)
        else:
            cleaned,counts=redact_text(original, (*RULES,*custom))
        if args.in_place:
            source.with_suffix(source.suffix+".bak").write_text(original,encoding="utf-8")
            source.write_text(cleaned,encoding="utf-8")
        elif args.output: Path(args.output).write_text(cleaned,encoding="utf-8")
        else: sys.stdout.write(cleaned)
        if args.summary:
            print(f"LogShield: redacted {sum(counts.values())} item(s).",file=sys.stderr)
            for name,count in sorted(counts.items()): print(f"  {name}: {count}",file=sys.stderr)
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"logshield: {exc}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
