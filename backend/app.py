"""
Flask API for SubFinderX web dashboard.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, request, send_file

from report_generator import generate_report
from scanner_wrapper import run_scan

app = Flask(__name__)

# In-memory history placeholder for now.
SCAN_HISTORY: list[Dict[str, Any]] = []
REPORT_INDEX: Dict[str, Dict[str, str]] = {}


def _cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


@app.after_request
def add_cors_headers(response):
    return _cors(response)


@app.route("/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        return _cors(jsonify({"ok": True}))

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
        return jsonify({"error": "Scanning allowed only on authorized targets"}), 403

    try:
        result = asyncio.run(
            run_scan(
                domain=domain,
                authorized=authorized,
                include_bruteforce=bool(payload.get("include_bruteforce", True)),
                scan_mode=scan_mode,
                wordlist_path=payload.get("wordlist_path"),
                user_wordlist_lines=wordlist_lines,
            )
        )
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    report_paths = generate_report(result)
    report_id = Path(report_paths["json_report"]).stem
    REPORT_INDEX[report_id] = report_paths

    response_payload = {**result, "report_id": report_id, "report_files": report_paths}
    SCAN_HISTORY.append({"domain": domain, "report_id": report_id, "scanned_at": result.get("scanned_at")})
    return jsonify(response_payload)


@app.route("/history", methods=["GET"])
def history():
    return jsonify({"history": SCAN_HISTORY})


@app.route("/report/<report_id>", methods=["GET"])
def download_report(report_id: str):
    report = REPORT_INDEX.get(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404

    fmt = request.args.get("format", "json").lower()
    report_key = "html_report" if fmt == "html" else "json_report"
    report_path = Path(report[report_key])
    if not report_path.exists():
        return jsonify({"error": "Report file missing"}), 404
    return send_file(report_path, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
