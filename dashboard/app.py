"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: dashboard/app.py — Web Dashboard Server (Flask)
===========================================================================
  Serves a live security operations dashboard at http://127.0.0.1:5000

  ROUTES:
    GET  /                  → Dashboard HTML page
    GET  /api/stats         → Summary KPI counts (JSON)
    GET  /api/devices       → All device records (JSON)
    GET  /api/events        → Recent 50 events (JSON)
    GET  /api/violations    → Recent violations (JSON)
    GET  /api/timeline      → Hourly event counts for chart (JSON)
    GET  /api/top-threats   → Top 5 highest-score devices (JSON)
    GET  /api/report        → Generate + download PDF report

  The dashboard auto-refreshes all data every 5 seconds using
  JavaScript fetch() — no WebSocket dependencies needed.

  HOW TO START:
    python dashboard/app.py
    Then open: http://127.0.0.1:5000
===========================================================================
"""

import sys
import os

# Make sure parent directory (usb_framework_v2/) is on the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, send_file
import config
from database import get_db

app = Flask(__name__,
            template_folder="templates",
            static_folder="static")

app.config["JSON_SORT_KEYS"] = False


# ──────────────────────────────────────────────────────────────────────────
# HTML route
# ──────────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("index.html",
                           org=config.ORGANIZATION,
                           version="2.0")


# ──────────────────────────────────────────────────────────────────────────
# JSON API routes
# ──────────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    try:
        return jsonify(get_db().get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/devices")
def api_devices():
    try:
        devices = get_db().get_all_devices()
        # Truncate long strings for the table
        for d in devices:
            if d.get("description") and len(d["description"]) > 35:
                d["description"] = d["description"][:33] + "…"
            if d.get("last_seen"):
                d["last_seen"] = d["last_seen"][:19].replace("T", " ")
            if d.get("first_seen"):
                d["first_seen"] = d["first_seen"][:19].replace("T", " ")
        return jsonify(devices)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/events")
def api_events():
    try:
        events = get_db().get_recent_events(limit=50)
        for e in events:
            if e.get("timestamp"):
                e["timestamp"] = e["timestamp"][:19].replace("T", " ")
            if e.get("details") and len(e["details"]) > 80:
                e["details"] = e["details"][:78] + "…"
        return jsonify(events)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/violations")
def api_violations():
    try:
        viols = get_db().get_violations(limit=20)
        for v in viols:
            if v.get("timestamp"):
                v["timestamp"] = v["timestamp"][:19].replace("T", " ")
        return jsonify(viols)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/timeline")
def api_timeline():
    try:
        return jsonify(get_db().get_hourly_timeline(24))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/top-threats")
def api_top_threats():
    try:
        threats = get_db().get_top_threats(limit=5)
        for t in threats:
            if t.get("last_seen"):
                t["last_seen"] = t["last_seen"][:19].replace("T", " ")
        return jsonify(threats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/report")
def api_report():
    """Generate a PDF report and return it as a download."""
    try:
        from pdf_reporter import PDFReporter
        import tempfile
        path = os.path.join(tempfile.gettempdir(), "usb_audit_report.pdf")
        PDFReporter().generate(output_path=path)
        return send_file(path,
                         as_attachment=True,
                         download_name="usb_audit_report.pdf",
                         mimetype="application/pdf")
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500


# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"""
  ╔══════════════════════════════════════════════════════╗
  ║  USB Security Dashboard  v2.0                       ║
  ║  http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}                       ║
  ║  Press Ctrl+C to stop                               ║
  ╚══════════════════════════════════════════════════════╝
  Tip: Run demo_seeder.py first to populate demo data.
""")
    app.run(
        host  = config.DASHBOARD_HOST,
        port  = config.DASHBOARD_PORT,
        debug = config.DASHBOARD_DEBUG
    )
