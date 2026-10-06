"""Render enrichment results as JSON, a terminal table, or an HTML report."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .engine import Enrichment
from .scoring import Band

_BAND_COLOUR = {
    Band.MALICIOUS: "#b4232a",
    Band.SUSPICIOUS: "#c9731b",
    Band.LOW: "#b8a21a",
    Band.CLEAN: "#2e7d32",
    Band.UNKNOWN: "#555",
}


def to_json(items: list[Enrichment]) -> str:
    return json.dumps([i.to_dict() for i in items], indent=2)


def to_table(items: list[Enrichment]) -> str:
    rows = [f"{'INDICATOR':<42}{'TYPE':<9}{'SCORE':<7}BAND"]
    rows.append("-" * 70)
    for it in items:
        score = "-" if it.score is None else f"{it.score:.0f}"
        rows.append(f"{it.indicator.value[:40]:<42}{it.indicator.type.value:<9}{score:<7}{it.band.value}")
    return "\n".join(rows)


def to_html(items: list[Enrichment]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = []
    for it in items:
        colour = _BAND_COLOUR[it.band]
        score = "n/a" if it.score is None else f"{it.score:.0f}/100"
        prov_rows = "".join(
            f"<tr><td>{html.escape(r.provider)}</td>"
            f"<td>{'-' if r.score is None else f'{r.score:.0f}'}</td>"
            f"<td>{html.escape(r.summary)}</td></tr>"
            for r in it.results
        )
        cards.append(f"""
        <div class="card">
          <div class="head">
            <span class="ioc">{html.escape(it.indicator.value)}</span>
            <span class="badge" style="background:{colour}">{it.band.value.upper()} &middot; {score}</span>
          </div>
          <div class="meta">type: {it.indicator.type.value}</div>
          <table>
            <thead><tr><th>Provider</th><th>Score</th><th>Summary</th></tr></thead>
            <tbody>{prov_rows}</tbody>
          </table>
        </div>""")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>IOC Enrichment Report</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f5f7;color:#1a1a1a}}
  header{{background:#13233a;color:#fff;padding:20px 28px}}
  header h1{{margin:0;font-size:19px}}
  header .sub{{opacity:.75;font-size:13px;margin-top:4px}}
  .wrap{{max-width:900px;margin:24px auto;padding:0 16px}}
  .card{{background:#fff;border:1px solid #e2e4e8;border-radius:8px;margin-bottom:16px;overflow:hidden}}
  .head{{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid #eee}}
  .ioc{{font-family:ui-monospace,Menlo,monospace;font-weight:600;word-break:break-all}}
  .badge{{color:#fff;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}}
  .meta{{padding:6px 16px;color:#666;font-size:12px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th,td{{text-align:left;padding:7px 16px;border-top:1px solid #f0f0f0}}
  th{{background:#fafbfc;color:#555;font-weight:600}}
</style></head>
<body>
  <header>
    <h1>IOC Enrichment Report</h1>
    <div class="sub">{len(items)} indicator(s) &middot; generated {generated}</div>
  </header>
  <div class="wrap">{''.join(cards)}</div>
</body></html>"""
