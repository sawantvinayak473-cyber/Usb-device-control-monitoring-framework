"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: dashboard/app.py — Web Dashboard Server (Flask)
===========================================================================
  CHANGE (this release): Added /api/file-events endpoint so the dashboard
  can display real-time file transfer activity from the USB drive.
===========================================================================
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template, send_file
import config
from database import get_db

app = Flask(__name__,
            template_folder="templates",
            static_folder="static")
app.config["JSON_SORT_KEYS"] = False


# ──────────────────────────────────────────────────────────────────────────
# HTML
# ──────────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("index.html",
                           org=config.ORGANIZATION,
                           version="2.0")


# ──────────────────────────────────────────────────────────────────────────
# JSON API
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
    """
    Returns the 50 most recent entries from the events table.
    This includes USB connect/disconnect events AND file events
    (FILE_CREATED, FILE_MODIFIED, etc.) because file_auditor.py
    now writes to both the file_events table and the events table.
    """
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


@app.route("/api/file-events")
def api_file_events():
    """
    Returns the 100 most recent file-transfer events from the file_events
    table with device VID/PID/serial joined in. Powers the dedicated file
    activity panel if added to the dashboard.
    """
    try:
        rows = get_db().get_file_events_summary(limit=100)
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"][:19].replace("T", " ")
            # Format file size for display
            sz = r.get("file_size", 0) or 0
            if sz > 1_048_576:
                r["file_size_display"] = f"{sz / 1_048_576:.1f} MB"
            elif sz > 1024:
                r["file_size_display"] = f"{sz / 1024:.1f} KB"
            elif sz > 0:
                r["file_size_display"] = f"{sz} B"
            else:
                r["file_size_display"] = ""
        return jsonify(rows)
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
  Tip: File events appear in Live Event Feed when USB is connected.
""")
    app.run(
        host  = config.DASHBOARD_HOST,
        port  = config.DASHBOARD_PORT,
        debug = config.DASHBOARD_DEBUG
    )
