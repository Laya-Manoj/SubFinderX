"""
Generate JSON, HTML, and PDF reports for completed scans.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

logger = logging.getLogger("subfinderx.reports")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

REPORTS_DIR = Path("backend") / "reports"


def _is_live_status(status: Any) -> bool:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return 200 <= code <= 399


def _status_label(entry: Dict[str, Any]) -> str:
    label = str(entry.get("status_label", "")).lower()
    if label in {"active", "inactive", "unverified"}:
        return label
    if entry.get("is_live") or _is_live_status(entry.get("status")):
        return "active"
    return "inactive"


def _partition_entries(data: Dict[str, Any]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    live: List[Dict[str, Any]] = []
    inactive: List[Dict[str, Any]] = []
    unverified: List[Dict[str, Any]] = []
    for entry in data.get("subdomains", []):
        name = str(entry.get("name", "")).strip()
        if not name or "*." in name:
            continue
        label = _status_label(entry)
        if label == "active":
            live.append(entry)
        elif label == "unverified":
            unverified.append(entry)
        else:
            inactive.append(entry)
    return live, inactive, unverified


def _clean_entries(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove wildcard entries and normalize report rows."""
    cleaned = dict(data)
    all_entries = []
    for entry in data.get("subdomains", []):
        name = str(entry.get("name", "")).strip()
        if not name or "*." in name:
            continue
        all_entries.append(entry)

    live_entries, inactive_entries, unverified_entries = _partition_entries({"subdomains": all_entries})
    dead_entries = inactive_entries + unverified_entries

    cleaned["subdomains"] = all_entries
    cleaned["live_subdomains"] = live_entries
    cleaned["unverified_subdomains"] = unverified_entries
    cleaned["dead_subdomains"] = [e.get("name", "") for e in dead_entries]
    cleaned["total_subdomains"] = len(all_entries)
    if "scan_summary" not in cleaned:
        open_ports_found = sum(len(e.get("open_ports") or []) for e in all_entries)
        cleaned["scan_summary"] = {
            "total": len(all_entries),
            "live": len(live_entries),
            "inactive": len(inactive_entries),
            "unverified": len(unverified_entries),
            "open_ports_found": open_ports_found,
        }
    return cleaned


def _build_html(data: Dict[str, Any]) -> str:
    cleaned_data = _clean_entries(data)
    live_entries = cleaned_data.get("live_subdomains", [])
    live_names = {e.get("name") for e in live_entries}
    dead_entries = [
        e
        for e in cleaned_data.get("subdomains", [])
        if e.get("name") not in live_names
    ]
    live_count = len(live_entries)
    dead_count = len(dead_entries)
    status_codes = data.get("status_codes", {})
    domain = cleaned_data.get("domain", "")
    scanned_at = cleaned_data.get("scanned_at", "")

    live_rows = []
    for entry in live_entries:
        missing_headers = entry.get("security_headers", {}).get("missing_headers", [])
        live_rows.append(
            "<tr>"
            f"<td>{entry.get('name', '')}</td>"
            f"<td>{entry.get('status', '')}</td>"
            f"<td>{entry.get('title', '')}</td>"
            f"<td>{entry.get('redirect_to', '') or '-'}</td>"
            f"<td>{', '.join(str(p) for p in entry.get('open_ports', []))}</td>"
            f"<td>{', '.join(missing_headers) if missing_headers else 'None'}</td>"
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

    unverified_entries = cleaned_data.get("unverified_subdomains", [])
    unverified_rows = []
    for entry in unverified_entries:
        unverified_rows.append(
            "<tr>"
            f"<td>{entry.get('name', '')}</td>"
            f"<td>Unverified</td>"
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
      <p>Live hosts analyzed (headers/ports): {cleaned_data.get('analyzed_live_subdomains', 0)}</p>
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
      <tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Redirect To</th><th>Open Ports</th><th>Missing Security Headers</th><th>Source</th></tr>
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
  <h2>Unverified Subdomains</h2>
  <table>
    <thead>
      <tr><th>Subdomain</th><th>Status</th><th>Source</th></tr>
    </thead>
    <tbody>
      {"".join(unverified_rows) if unverified_rows else "<tr><td colspan='3'>None</td></tr>"}
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


# PDF theme constants
_PDF_BG = colors.HexColor("#0a0a0a")
_PDF_PANEL = colors.HexColor("#1a1a1a")
_PDF_PANEL_ALT = colors.HexColor("#141414")
_PDF_HEADER_BG = colors.HexColor("#2a2a2a")
_PDF_ACCENT = colors.HexColor("#ff3b3b")
_PDF_HEADER_TEXT = colors.HexColor("#ff8d8d")
_PDF_BODY_TEXT = colors.HexColor("#e5e5e5")
_PDF_MUTED_TEXT = colors.HexColor("#b3b3b3")
_PDF_GRID = colors.HexColor("#3a3a3a")
_PDF_PAGE_WIDTH, _PDF_PAGE_HEIGHT = letter
_PDF_MARGIN = 0.6 * inch
_PDF_CONTENT_WIDTH = _PDF_PAGE_WIDTH - (2 * _PDF_MARGIN)
_PDF_FOOTER_Y = 0.42 * inch


def _pdf_display(value: Any) -> str:
    """Normalize scalar values for PDF (plain text, escaped later in Paragraphs)."""
    if value is None:
        return "N/A"
    text = str(value).strip()
    if not text or text.lower() in {"-", "none", "null", "n/a"}:
        return "N/A"
    return text


def _pdf_join(values: Optional[Sequence[Any]], sep: str = ", ") -> str:
    if not values:
        return "N/A"
    cleaned = [_pdf_display(v) for v in values]
    cleaned = [v for v in cleaned if v != "N/A"]
    return sep.join(cleaned) if cleaned else "N/A"


def _pdf_missing_headers_html(headers: Optional[List[str]]) -> str:
    if not headers:
        return "N/A"
    items = [escape(str(h).strip()) for h in headers if str(h).strip()]
    if not items:
        return "N/A"
    return "<br/>".join(f"&bull; {item}" for item in items)


def _build_pdf_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "PdfTitle",
            parent=base["Heading1"],
            textColor=_PDF_ACCENT,
            fontSize=18,
            leading=22,
            spaceAfter=10,
            fontName="Helvetica-Bold",
        ),
        "section": ParagraphStyle(
            "PdfSection",
            parent=base["Heading2"],
            textColor=_PDF_BODY_TEXT,
            fontSize=12,
            leading=15,
            spaceBefore=14,
            spaceAfter=8,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "PdfBody",
            parent=base["Normal"],
            textColor=_PDF_BODY_TEXT,
            fontSize=10,
            leading=14,
        ),
        "muted": ParagraphStyle(
            "PdfMuted",
            parent=base["Normal"],
            textColor=_PDF_MUTED_TEXT,
            fontSize=9,
            leading=12,
        ),
        "empty": ParagraphStyle(
            "PdfEmpty",
            parent=base["Normal"],
            textColor=_PDF_MUTED_TEXT,
            fontSize=9,
            leading=12,
            leftIndent=4,
            spaceBefore=4,
            spaceAfter=10,
            fontName="Helvetica-Oblique",
        ),
        "cell": ParagraphStyle(
            "PdfCell",
            parent=base["Normal"],
            textColor=_PDF_BODY_TEXT,
            fontSize=8,
            leading=11,
            wordWrap="CJK",
            alignment=TA_LEFT,
        ),
        "cell_header": ParagraphStyle(
            "PdfCellHeader",
            parent=base["Normal"],
            textColor=_PDF_HEADER_TEXT,
            fontSize=9,
            leading=12,
            fontName="Helvetica-Bold",
            alignment=TA_LEFT,
        ),
        "summary_label": ParagraphStyle(
            "PdfSummaryLabel",
            parent=base["Normal"],
            textColor=_PDF_MUTED_TEXT,
            fontSize=8,
            leading=10,
            alignment=TA_CENTER,
        ),
        "summary_value": ParagraphStyle(
            "PdfSummaryValue",
            parent=base["Normal"],
            textColor=_PDF_BODY_TEXT,
            fontSize=14,
            leading=16,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
    }


def _pdf_para(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text, style)


def _pdf_cell(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(_pdf_display(text)), style)


def _pdf_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), _PDF_HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), _PDF_HEADER_TEXT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), _PDF_PANEL),
            ("TEXTCOLOR", (0, 1), (-1, -1), _PDF_BODY_TEXT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_PDF_PANEL, _PDF_PANEL_ALT]),
            ("GRID", (0, 0), (-1, -1), 0.25, _PDF_GRID),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 1), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        ]
    )


def _build_pdf_data_table(
    headers: List[str],
    rows: List[List[Paragraph]],
    col_widths: List[float],
    header_style: ParagraphStyle,
) -> Table:
    header_row = [_pdf_para(f"<b>{escape(h)}</b>", header_style) for h in headers]
    table = Table([header_row, *rows], colWidths=col_widths, repeatRows=1, splitByRow=1)
    table.setStyle(_pdf_table_style())
    return table


def _build_pdf_summary_cards(summary: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    labels = ["Total Subdomains", "Live", "Inactive", "Unverified", "Open Ports"]
    keys = ["total", "live", "inactive", "unverified", "open_ports_found"]
    col_w = _PDF_CONTENT_WIDTH / len(labels)
    label_row = [_pdf_para(escape(label), styles["summary_label"]) for label in labels]
    value_row = [
        _pdf_para(escape(str(summary.get(key, 0))), styles["summary_value"]) for key in keys
    ]
    table = Table([label_row, value_row], colWidths=[col_w] * len(labels))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _PDF_HEADER_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, _PDF_GRID),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, _PDF_GRID),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _build_pdf_page_callback(scanned_at: str):
    def _draw_page(canvas, doc_obj) -> None:
        canvas.saveState()
        canvas.setFillColor(_PDF_BG)
        canvas.rect(0, 0, _PDF_PAGE_WIDTH, _PDF_PAGE_HEIGHT, fill=1, stroke=0)

        canvas.setStrokeColor(_PDF_GRID)
        canvas.setLineWidth(0.5)
        canvas.line(_PDF_MARGIN, _PDF_FOOTER_Y + 0.14 * inch, _PDF_PAGE_WIDTH - _PDF_MARGIN, _PDF_FOOTER_Y + 0.14 * inch)

        canvas.setFillColor(_PDF_MUTED_TEXT)
        canvas.setFont("Helvetica", 8)
        footer = (
            f"Generated by SubFinderX  |  Scan: {scanned_at or 'N/A'}  |  "
            f"Page {canvas.getPageNumber()}"
        )
        canvas.drawCentredString(_PDF_PAGE_WIDTH / 2.0, _PDF_FOOTER_Y, footer)
        canvas.restoreState()

    return _draw_page


def _append_pdf_section(
    story: List[Any],
    title: str,
    styles: Dict[str, ParagraphStyle],
    headers: List[str],
    row_builder,
    entries: List[Dict[str, Any]],
    col_widths: List[float],
    empty_message: str,
) -> None:
    story.append(_pdf_para(f"<b>{escape(title)}</b>", styles["section"]))
    if not entries:
        story.append(_pdf_para(escape(empty_message), styles["empty"]))
        return
    rows = row_builder(entries, styles["cell"])
    story.append(_build_pdf_data_table(headers, rows, col_widths, styles["cell_header"]))


def _build_pdf(data: Dict[str, Any], pdf_path: Path) -> None:
    """Render a dark-themed PDF report with wrapped cells and multi-page tables."""
    cleaned = _clean_entries(data)
    live_entries, inactive_entries, unverified_entries = _partition_entries(cleaned)
    summary = cleaned.get("scan_summary", {})
    domain = _pdf_display(cleaned.get("domain", "unknown"))
    scanned_at = _pdf_display(cleaned.get("scanned_at", ""))
    scan_mode = _pdf_display(cleaned.get("scan_mode", "unknown"))

    styles = _build_pdf_styles()
    cell = styles["cell"]

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=_PDF_MARGIN,
        rightMargin=_PDF_MARGIN,
        topMargin=_PDF_MARGIN,
        bottomMargin=0.85 * inch,
    )

    # Column widths: subdomain wide, missing headers widest, status/ports/source small
    live_col_widths = [
        2.05 * inch,  # Subdomain
        0.55 * inch,  # Status
        1.45 * inch,  # Title
        0.6 * inch,   # Open Ports
        2.65 * inch,  # Missing Headers
    ]
    three_col_widths = [
        3.6 * inch,   # Subdomain
        0.75 * inch,  # Status
        2.95 * inch,  # Source
    ]

    def _live_rows(entries: List[Dict[str, Any]], cell_style: ParagraphStyle) -> List[List[Paragraph]]:
        built: List[List[Paragraph]] = []
        for entry in entries:
            ports = entry.get("open_ports") or []
            missing = entry.get("security_headers", {}).get("missing_headers", [])
            built.append(
                [
                    _pdf_cell(entry.get("name", ""), cell_style),
                    _pdf_cell(entry.get("status", ""), cell_style),
                    _pdf_cell(entry.get("title", ""), cell_style),
                    _pdf_cell(_pdf_join(ports), cell_style),
                    Paragraph(_pdf_missing_headers_html(missing), cell_style),
                ]
            )
        return built

    def _inactive_rows(entries: List[Dict[str, Any]], cell_style: ParagraphStyle) -> List[List[Paragraph]]:
        built: List[List[Paragraph]] = []
        for entry in entries:
            status = entry.get("status")
            status_text = _pdf_display(status) if status is not None else "No HTTP response"
            built.append(
                [
                    _pdf_cell(entry.get("name", ""), cell_style),
                    _pdf_cell(status_text, cell_style),
                    _pdf_cell(_pdf_join(entry.get("source") or []), cell_style),
                ]
            )
        return built

    def _unverified_rows(entries: List[Dict[str, Any]], cell_style: ParagraphStyle) -> List[List[Paragraph]]:
        built: List[List[Paragraph]] = []
        for entry in entries:
            built.append(
                [
                    _pdf_cell(entry.get("name", ""), cell_style),
                    _pdf_cell("Unverified", cell_style),
                    _pdf_cell(_pdf_join(entry.get("source") or []), cell_style),
                ]
            )
        return built

    story: List[Any] = [
        _pdf_para("<b>SubFinderX — Attack Surface Report</b>", styles["title"]),
        _pdf_para(f"<b>Target:</b> {escape(domain)}", styles["body"]),
        _pdf_para(f"<b>Generated:</b> {escape(scanned_at)}", styles["muted"]),
        _pdf_para(f"<b>Scan mode:</b> {escape(scan_mode)}", styles["muted"]),
        Spacer(1, 0.18 * inch),
        _pdf_para("<b>Scan Summary</b>", styles["section"]),
        _build_pdf_summary_cards(summary, styles),
        Spacer(1, 0.2 * inch),
    ]

    if live_entries:
        _append_pdf_section(
            story,
            "Live Subdomains",
            styles,
            ["Subdomain", "Status", "Title", "Open Ports", "Missing Headers"],
            _live_rows,
            live_entries,
            live_col_widths,
            "No live subdomains found.",
        )
    else:
        story.append(_pdf_para("<b>Live Subdomains</b>", styles["section"]))
        story.append(_pdf_para("No live subdomains found.", styles["empty"]))

    story.append(Spacer(1, 0.12 * inch))
    _append_pdf_section(
        story,
        "Inactive Subdomains",
        styles,
        ["Subdomain", "Status", "Source"],
        _inactive_rows,
        inactive_entries,
        three_col_widths,
        "No inactive subdomains found.",
    )

    story.append(Spacer(1, 0.12 * inch))
    _append_pdf_section(
        story,
        "Unverified Subdomains",
        styles,
        ["Subdomain", "Status", "Source"],
        _unverified_rows,
        unverified_entries,
        three_col_widths,
        "No unverified subdomains found.",
    )

    page_cb = _build_pdf_page_callback(scanned_at if scanned_at != "N/A" else "")
    doc.build(story, onFirstPage=page_cb, onLaterPages=page_cb)


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

    pdf_path = REPORTS_DIR / f"{file_base}.pdf"
    try:
        _build_pdf(cleaned_data, pdf_path)
        logger.info("PDF generated: %s", pdf_path)
    except Exception as exc:
        logger.error("PDF generation failed: %s", exc)
        pdf_path = None

    paths = {"json_report": str(json_path), "html_report": str(html_path)}
    if pdf_path and pdf_path.exists():
        paths["pdf_report"] = str(pdf_path)
    return paths
