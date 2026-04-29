"""
Generate JSON and HTML reports for completed scans.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


REPORTS_DIR = Path("backend") / "reports"


def _is_live_status(status: Any) -> bool:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return 200 <= code <= 399


def _clean_entries(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove wildcard entries and normalize report rows."""
    cleaned = dict(data)
    all_entries = []
    for entry in data.get("subdomains", []):
        name = str(entry.get("name", "")).strip()
        if not name or "*." in name:
            continue
        all_entries.append(entry)

    live_entries = [e for e in all_entries if _is_live_status(e.get("status"))]
    dead_entries = [e for e in all_entries if not _is_live_status(e.get("status"))]

    cleaned["subdomains"] = all_entries
    cleaned["live_subdomains"] = live_entries
    cleaned["dead_subdomains"] = [e.get("name", "") for e in dead_entries]
    cleaned["total_subdomains"] = len(all_entries)
    return cleaned


def _build_html(data: Dict[str, Any]) -> str:
    cleaned_data = _clean_entries(data)
    live_entries = cleaned_data.get("live_subdomains", [])
    dead_entries = [e for e in cleaned_data.get("subdomains", []) if not _is_live_status(e.get("status"))]
    live_count = len(live_entries)
    dead_count = len(dead_entries)
    status_codes = data.get("status_codes", {})
    domain = cleaned_data.get("domain", "")
    scanned_at = cleaned_data.get("scanned_at", "")

    live_rows = []
    for entry in live_entries:
        live_rows.append(
            "<tr>"
            f"<td>{entry.get('name', '')}</td>"
            f"<td>{entry.get('status', '')}</td>"
            f"<td>{entry.get('title', '')}</td>"
            f"<td>{entry.get('redirect_to', '') or '-'}</td>"
            f"<td>{', '.join(str(p) for p in entry.get('open_ports', []))}</td>"
            f"<td>{', '.join(entry.get('source', []))}</td>"
            "</tr>"
        )

    dead_rows = []
    for entry in dead_entries:
        dead_rows.append(
            "<tr>"
            f"<td>{entry.get('name', '')}</td>"
            f"<td>{entry.get('status', '') or 'No HTTP response'}</td>"
            f"<td>{', '.join(entry.get('source', []))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>SubFinderX: Attack Surface Analyzer Report - {domain}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(280px, 1fr)); gap: 16px; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 14px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background-color: #f6f6f6; }}
  </style>
</head>
<body>
  <h1>SubFinderX: Attack Surface Analyzer Report</h1>
  <p><strong>SubFinderX: Attack Surface Analyzer</strong></p>
  <p><strong>Report for:</strong> {domain}</p>
  <p><strong>Generated on:</strong> {scanned_at}</p>
  <div class="grid">
    <div class="card">
      <h3>Summary</h3>
      <p>Total subdomains: {cleaned_data.get('total_subdomains', 0)}</p>
      <p>Live: {live_count}</p>
      <p>Dead: {dead_count}</p>
      <p>Passive count: {cleaned_data.get('passive_count', 0)}</p>
      <p>Brute-force count: {cleaned_data.get('brute_force_count', 0)}</p>
      <p>Wordlist entries used: {cleaned_data.get('wordlist', {}).get('combined_entries', 0)}</p>
    </div>
    <div class="card">
      <canvas id="liveChart"></canvas>
    </div>
    <div class="card">
      <canvas id="statusChart"></canvas>
    </div>
  </div>
  <h2>Live Subdomains</h2>
  <table>
    <thead>
      <tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Redirect To</th><th>Open Ports</th><th>Source</th></tr>
    </thead>
    <tbody>
      {"".join(live_rows)}
    </tbody>
  </table>
  <h2>Inactive / Dead Subdomains</h2>
  <table>
    <thead>
      <tr><th>Subdomain</th><th>Status</th><th>Source</th></tr>
    </thead>
    <tbody>
      {"".join(dead_rows)}
    </tbody>
  </table>
  <script>
    const statusCodes = {json.dumps(status_codes)};
    new Chart(document.getElementById('liveChart'), {{
      type: 'pie',
      data: {{
        labels: ['Live', 'Dead'],
        datasets: [{{ data: [{live_count}, {dead_count}] }}]
      }}
    }});

    new Chart(document.getElementById('statusChart'), {{
      type: 'bar',
      data: {{
        labels: Object.keys(statusCodes),
        datasets: [{{ label: 'Status Codes', data: Object.values(statusCodes) }}]
      }}
    }});
  </script>
</body>
</html>
"""


def generate_report(data: Dict[str, Any]) -> Dict[str, str]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    cleaned_data = _clean_entries(data)
    domain = cleaned_data.get("domain", "unknown-domain").replace(".", "_")
    file_base = f"subfinderx_report_{domain}"

    json_path = REPORTS_DIR / f"{file_base}.json"
    html_path = REPORTS_DIR / f"{file_base}.html"

    with json_path.open("w", encoding="utf-8") as json_file:
        json.dump(cleaned_data, json_file, indent=2)

    html_path.write_text(_build_html(cleaned_data), encoding="utf-8")

    return {"json_report": str(json_path), "html_report": str(html_path)}
