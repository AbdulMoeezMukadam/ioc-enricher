"""Command-line interface for the IOC enricher."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import Engine
from .report import to_html, to_json, to_table


def _read_inputs(args) -> list[str]:
    values: list[str] = list(args.indicator)
    if args.input_file:
        text = Path(args.input_file).read_text(encoding="utf-8", errors="ignore")
        values.extend(line for line in text.splitlines() if line.strip())
    if not values and not sys.stdin.isatty():
        values.extend(line for line in sys.stdin.read().splitlines() if line.strip())
    return values


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iocenrich",
        description="Enrich IPs, domains, URLs and hashes against threat-intel feeds.",
    )
    p.add_argument("indicator", nargs="*", help="one or more indicators")
    p.add_argument("-f", "--input-file", help="file with one indicator per line")
    p.add_argument("-o", "--output", help="write report to this path")
    p.add_argument(
        "--format", choices=["table", "json", "html"], default="table",
        help="output format (default: table)",
    )
    p.add_argument("--version", action="version", version=f"iocenrich {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    indicators = _read_inputs(args)
    if not indicators:
        print("no indicators supplied; pass them as arguments, with -f, or on stdin",
              file=sys.stderr)
        return 2

    results = Engine().enrich_many(indicators)

    renderers = {"table": to_table, "json": to_json, "html": to_html}
    rendered = renderers[args.format](results)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.format} report for {len(results)} indicator(s) to {args.output}",
              file=sys.stderr)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
