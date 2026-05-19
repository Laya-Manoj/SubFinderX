"""
Flask API for SubFinderX web dashboard.
"""

from __future__ import annotations

import asyncio
import logging
import os
import traceback
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from report_generator import generate_report
from scanner_wrapper import run_scan

logger = logging.getLogger("subfinderx.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

app = Flask(__name__)
CORS(app)

SCAN_HISTORY: list[Dict[str, Any]] = []
REPORT_INDEX: Dict[str, Dict[str, str]] = {}


def run_async_safe(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)


@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) if request.is_json else request.form.to_dict()
    payload = payload or {}

    domain = str(payload.get("domain", "")).strip().lower()
    authorized = bool(payload.get("authorized", True))
    scan_mode = str(payload.get("scan_mode", "quick")).strip().lower()

    wordlist_text = str(payload.get("wordlist_text", "")).strip()
    wordlist_lines = wordlist_text.splitlines() if wordlist_text else []

    uploaded_file = request.files.get("wordlist_file")
    if uploaded_file and uploaded_file.filename:
        decoded = uploaded_file.read().decode("utf-8", errors="ignore")
        wordlist_lines.extend(decoded.splitlines())

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    if not authorized:
        return jsonify({"error": "Unauthorized scan"}), 403

    try:
        if scan_mode == "quick":
            timeout = 28
            include_bruteforce = False
        else:
            timeout = 120
            include_bruteforce = True

        logger.info("scan started: domain=%s mode=%s", domain, scan_mode)

        async def limited_scan():
            return await asyncio.wait_for(
                run_scan(
                    domain=domain,
                    authorized=authorized,
                    include_bruteforce=include_bruteforce,
                    scan_mode=scan_mode,
                    wordlist_path=payload.get("wordlist_path"),
                    user_wordlist_lines=wordlist_lines,
                ),
                timeout=timeout,
            )

        result = run_async_safe(limited_scan())

    except asyncio.TimeoutError:
        logger.warning("scan timeout: domain=%s mode=%s", domain, scan_mode)
        return jsonify(
            {
                "domain": domain,
                "scan_mode": scan_mode,
                "subdomains": [],
                "total_found": 0,
                "total_subdomains": 0,
                "live_subdomains": [],
                "unverified_subdomains": [],
                "dead_subdomains": [],
                "status_codes": {},
                "classified": {"admin": [], "api": [], "dev": [], "others": []},
                "scan_summary": {
                    "total": 0,
                    "live": 0,
                    "inactive": 0,
                    "unverified": 0,
                    "open_ports_found": 0,
                },
                "warning": "Scan reached timeout; returning partial results.",
            }
        ), 200

    except Exception as e:
        logger.error("scan error: domain=%s error=%s", domain, e)
        traceback.print_exc()
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    report_paths = generate_report(result)
    report_id = Path(report_paths["json_report"]).stem
    REPORT_INDEX[report_id] = report_paths

    SCAN_HISTORY.append(
        {
            "domain": domain,
            "report_id": report_id,
            "scanned_at": result.get("scanned_at"),
        }
    )

    logger.info("scan completed: domain=%s report_id=%s", domain, report_id)

    return jsonify(
        {
            **result,
            "report_id": report_id,
            "report_files": report_paths,
        }
    )


@app.route("/history", methods=["GET"])
def history():
    return jsonify({"history": SCAN_HISTORY})


@app.route("/report/<report_id>", methods=["GET"])
def download_report(report_id: str):
    report = REPORT_INDEX.get(report_id)

    if not report:
        return jsonify({"error": "Report not found"}), 404

    fmt = request.args.get("format", "json").lower()
    if fmt == "html":
        report_key = "html_report"
    elif fmt == "pdf":
        report_key = "pdf_report"
    else:
        report_key = "json_report"

    report_path_value = report.get(report_key)
    if not report_path_value:
        return jsonify({"error": f"Report format '{fmt}' not available"}), 404

    report_path = Path(report_path_value)
    if not report_path.exists():
        return jsonify({"error": "File missing"}), 404

    mimetype = None
    if fmt == "pdf":
        mimetype = "application/pdf"

    return send_file(report_path, as_attachment=True, mimetype=mimetype)


@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "SubFinderX backend running"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
