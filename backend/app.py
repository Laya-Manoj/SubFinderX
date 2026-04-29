"""
Flask API for SubFinderX web dashboard.
"""

from __future__ import annotations

import asyncio
import os
import traceback
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from report_generator import generate_report
from scanner_wrapper import run_scan

app = Flask(__name__)
CORS(app)  # Enable CORS properly

# In-memory storage (temporary)
SCAN_HISTORY: list[Dict[str, Any]] = []
REPORT_INDEX: Dict[str, Dict[str, str]] = {}


# ---------------------------
# SAFE ASYNC RUNNER (IMPORTANT)
# ---------------------------
def run_async_safe(coro):
    """
    Runs async function safely inside Flask/Gunicorn
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)


# ---------------------------
# SCAN ENDPOINT
# ---------------------------
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
        # ---------------------------
        # TIME-LIMITED SCAN (IMPORTANT)
        # ---------------------------
        async def limited_scan():
            return await asyncio.wait_for(
                run_scan(
                    domain=domain,
                    authorized=authorized,
                    include_bruteforce=True,  # KEEP BRUTEFORCE
                    scan_mode=scan_mode,
                    wordlist_path=payload.get("wordlist_path"),
                    user_wordlist_lines=wordlist_lines,
                ),
                timeout=20  # prevent Render timeout death
            )

        result = run_async_safe(limited_scan())

    except asyncio.TimeoutError:
        return jsonify({"error": "Scan timed out (server limit reached)"}), 408

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # ---------------------------
    # REPORT GENERATION
    # ---------------------------
    report_paths = generate_report(result)
    report_id = Path(report_paths["json_report"]).stem

    REPORT_INDEX[report_id] = report_paths

    SCAN_HISTORY.append({
        "domain": domain,
        "report_id": report_id,
        "scanned_at": result.get("scanned_at")
    })

    return jsonify({
        **result,
        "report_id": report_id,
        "report_files": report_paths
    })


# ---------------------------
# HISTORY ENDPOINT
# ---------------------------
@app.route("/history", methods=["GET"])
def history():
    return jsonify({"history": SCAN_HISTORY})


# ---------------------------
# REPORT DOWNLOAD
# ---------------------------
@app.route("/report/<report_id>", methods=["GET"])
def download_report(report_id: str):
    report = REPORT_INDEX.get(report_id)

    if not report:
        return jsonify({"error": "Report not found"}), 404

    fmt = request.args.get("format", "json").lower()
    report_key = "html_report" if fmt == "html" else "json_report"

    report_path = Path(report[report_key])

    if not report_path.exists():
        return jsonify({"error": "File missing"}), 404

    return send_file(report_path, as_attachment=True)


# ---------------------------
# HEALTH CHECK (VERY USEFUL)
# ---------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "SubFinderX backend running"})


# ---------------------------
# ENTRY POINT
# ---------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)