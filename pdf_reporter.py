"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: pdf_reporter.py -- Professional PDF Report with Charts
===========================================================================
  Generates a polished, multi-page PDF audit report containing:

    Page 1  -- Cover page with org name, timestamp, risk level badge
    Page 2  -- Executive summary table + KPI metrics
    Page 3  -- Bar chart: event counts by type
    Page 3  -- Pie chart: device status breakdown
    Page 4  -- Line chart: hourly event activity (24 h)
    Page 5  -- Violations table (all recorded incidents)
    Page 6  -- Top threat devices table
    Page 7  -- Recommendations & sign-off

  Libraries used:
    matplotlib -- chart generation (saves charts as PNG, embedded in PDF)
    fpdf2      -- PDF layout, text, tables, image embedding
===========================================================================
"""

import os
import tempfile
from datetime import datetime
from typing import List, Dict

import matplotlib
matplotlib.use("Agg")          # Non-interactive backend (no display needed)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from fpdf import FPDF

import config

def _safe(s):
    return str(s).encode("latin-1",errors="replace").decode("latin-1")

from database import get_db


# ── Colour palette ─────────────────────────────────────────────────────────
NAVY   = (13,  27,  42)
BLUE   = (30, 139, 195)
TEAL   = (20, 143, 119)
RED    = (192, 57,  43)
AMBER  = (211,165,  31)
WHITE  = (255, 255, 255)
LGRAY  = (240, 244, 248)
MGRAY  = (160, 175, 190)


def _rgb(t): return tuple(c/255 for c in t)   # matplotlib uses 0-1 floats


# ══════════════════════════════════════════════════════════════════════════
# Chart generators (return temp file paths)
# ══════════════════════════════════════════════════════════════════════════

def _chart_event_types(events: List[Dict], tmp_dir: str) -> str:
    types  = {}
    for e in events:
        t = e.get("event_type", "OTHER")
        types[t] = types.get(t, 0) + 1

    labels = list(types.keys())
    values = list(types.values())
    colors = [_rgb(BLUE), _rgb(TEAL), _rgb(RED), _rgb(AMBER),
              _rgb(MGRAY)] * 10

    fig, ax = plt.subplots(figsize=(9, 4), facecolor=_rgb(LGRAY))
    ax.set_facecolor(_rgb(LGRAY))
    bars = ax.bar(labels, values, color=colors[:len(labels)],
                  edgecolor="white", linewidth=0.5, zorder=3)
    ax.bar_label(bars, padding=3, fontsize=9, color=_rgb(NAVY))
    ax.set_title("Event Counts by Type", fontsize=13, color=_rgb(NAVY),
                 fontweight="bold", pad=12)
    ax.set_ylabel("Count", fontsize=10, color=_rgb(NAVY))
    ax.tick_params(colors=_rgb(NAVY), labelsize=9)
    ax.spines[["top","right"]].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    path = os.path.join(tmp_dir, "chart_events.png")
    plt.savefig(path, dpi=150, bbox_inches="tight",
                facecolor=_rgb(LGRAY))
    plt.close()
    return path


def _chart_device_pie(stats: Dict, tmp_dir: str) -> str:
    labels = ["Authorized", "Blocked", "Suspicious", "Unknown"]
    values = [
        stats.get("allowed_devices",    0),
        stats.get("blocked_devices",    0),
        stats.get("suspicious_devices", 0),
        stats.get("unknown_devices",    0),
    ]
    colors = [_rgb(TEAL), _rgb(RED), _rgb(AMBER), _rgb(MGRAY)]
    values_nz = [max(v, 0.001) for v in values]   # avoid zero-slice errors

    fig, ax = plt.subplots(figsize=(6, 5), facecolor=_rgb(LGRAY))
    wedges, texts, autotexts = ax.pie(
        values_nz, labels=labels, colors=colors,
        autopct=lambda p: f"{p:.0f}%" if p > 1 else "",
        startangle=90, pctdistance=0.75,
        wedgeprops={"edgecolor": "white", "linewidth": 1.5}
    )
    for t in texts:
        t.set_fontsize(10); t.set_color(_rgb(NAVY))
    for at in autotexts:
        at.set_fontsize(9); at.set_color("white"); at.set_fontweight("bold")
    ax.set_title("Device Status Breakdown", fontsize=13, color=_rgb(NAVY),
                 fontweight="bold", pad=14)
    plt.tight_layout()
    path = os.path.join(tmp_dir, "chart_pie.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_rgb(LGRAY))
    plt.close()
    return path


def _chart_hourly_timeline(timeline: Dict, tmp_dir: str) -> str:
    labels = timeline.get("labels", [f"{h:02d}:00" for h in range(24)])
    ev     = timeline.get("events",     [0]*24)
    vi     = timeline.get("violations", [0]*24)

    fig, ax = plt.subplots(figsize=(12, 4), facecolor=_rgb(LGRAY))
    ax.set_facecolor(_rgb(LGRAY))
    ax.plot(labels, ev, color=_rgb(BLUE), linewidth=2,
            marker="o", markersize=4, label="Events", zorder=3)
    ax.fill_between(labels, ev, alpha=0.12, color=_rgb(BLUE))
    ax.plot(labels, vi, color=_rgb(RED), linewidth=2,
            marker="s", markersize=4, label="Violations", zorder=3)
    ax.fill_between(labels, vi, alpha=0.12, color=_rgb(RED))
    ax.set_title("USB Activity -- Last 24 Hours", fontsize=13,
                 color=_rgb(NAVY), fontweight="bold", pad=12)
    ax.set_ylabel("Count", fontsize=10, color=_rgb(NAVY))
    ax.tick_params(colors=_rgb(NAVY), labelsize=8)
    ax.spines[["top","right"]].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(fontsize=9, framealpha=0.5)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    path = os.path.join(tmp_dir, "chart_timeline.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_rgb(LGRAY))
    plt.close()
    return path


# ══════════════════════════════════════════════════════════════════════════
# PDF builder
# ══════════════════════════════════════════════════════════════════════════

class _PDF(FPDF):
    """Custom FPDF subclass with header/footer and helper methods."""

    def header(self):
        # Dark navy header bar
        self.set_fill_color(*NAVY)
        self.rect(0, 0, 210, 14, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_xy(8, 3.5)
        self.cell(0, 7, "USB Device Control & Monitoring Framework  v2.0  |  "
                         "Confidential Security Audit Report")

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(*BLUE)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MGRAY)
        self.cell(0, 8, f"Page {self.page_no()} / {{nb}}  |  "
                         f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
                         f"{config.ORGANIZATION}",
                  align="C")

    def section_title(self, text: str):
        self.ln(6)
        self.set_fill_color(*BLUE)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, f"  {text}", ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def kpi_card(self, label: str, value: str, color: tuple, x: float, y: float):
        self.set_fill_color(*color)
        self.rect(x, y, 42, 18, "F")
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 18)
        self.set_xy(x + 1, y + 2)
        self.cell(40, 9, value, align="C")
        self.set_font("Helvetica", "", 8)
        self.set_xy(x + 1, y + 11)
        self.cell(40, 5, label, align="C")
        self.set_text_color(0, 0, 0)

    def table_header(self, cols: list):
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 9)
        for label, w in cols:
            self.cell(w, 7, str(label).encode("latin-1",errors="replace").decode("latin-1"), border=0, fill=True, align="C")
        self.ln()
        self.set_text_color(0, 0, 0)

    def table_row(self, values: list, widths: list, shade: bool = False):
        self.set_fill_color(*(LGRAY if shade else WHITE))
        self.set_font("Helvetica", "", 8)
        for val, w in zip(values, widths):
            self.cell(w, 6, str(val).encode("latin-1",errors="replace").decode("latin-1")[:40], border=0, fill=True)
        self.ln()


class PDFReporter:
    """Generates a professional PDF audit report from the SQLite database."""

    def generate(self, output_path: str = None) -> str:
        db  = get_db()
        stats      = db.get_stats()
        events     = db.get_recent_events(limit=500)
        violations = db.get_violations(limit=100)
        devices    = db.get_all_devices()
        timeline   = db.get_hourly_timeline(24)
        top_threats= db.get_top_threats(limit=8)

        # Determine overall risk level
        if stats["critical_threats"] > 0 or stats["blocked_devices"] > 0:
            risk_label, risk_color = "HIGH RISK", RED
        elif stats["high_threats"] > 0:
            risk_label, risk_color = "MEDIUM RISK", AMBER
        else:
            risk_label, risk_color = "LOW RISK", TEAL

        # Generate charts into a temp directory
        tmp = tempfile.mkdtemp()
        try:
            chart_events   = _chart_event_types(events, tmp)
            chart_pie      = _chart_device_pie(stats, tmp)
            chart_timeline = _chart_hourly_timeline(timeline, tmp)
        except Exception as e:
            chart_events = chart_pie = chart_timeline = None

        # ── Build PDF ──────────────────────────────────────────────────
        pdf = _PDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=16)

        # ── COVER PAGE ─────────────────────────────────────────────────
        pdf.add_page()
        pdf.set_fill_color(*NAVY)
        pdf.rect(0, 14, 210, 70, "F")

        pdf.set_xy(0, 30)
        pdf.set_font("Helvetica", "B", 26)
        pdf.set_text_color(*WHITE)
        pdf.cell(210, 12, "USB Device Control &", align="C", ln=True)
        pdf.cell(210, 12, "Monitoring Framework", align="C", ln=True)
        pdf.set_font("Helvetica", "", 14)
        pdf.set_text_color(*MGRAY)
        pdf.cell(210, 8, "Security Audit Report  |  v2.0", align="C", ln=True)

        # Risk badge
        pdf.set_fill_color(*risk_color)
        pdf.set_xy(75, 74)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*WHITE)
        pdf.cell(60, 10, risk_label, align="C", fill=True)
        pdf.set_text_color(0, 0, 0)

        # Meta block
        pdf.set_xy(30, 100)
        pdf.set_font("Helvetica", "", 11)
        meta = [
            ("Organization",  config.ORGANIZATION),
            ("Generated",      datetime.now().strftime("%d %B %Y  %H:%M:%S")),
            ("Classification", "CONFIDENTIAL -- Internal Use Only"),
            ("Framework",      "USB Device Control & Monitoring Framework v2.0"),
        ]
        for k, v in meta:
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_x(30); pdf.cell(45, 8, k + ":")
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 8, _safe(str(v)), ln=True)

        # ── PAGE 2: EXECUTIVE SUMMARY ──────────────────────────────────
        pdf.add_page()
        pdf.section_title("1.  Executive Summary")

        # KPI cards
        kpis = [
            ("Total Events",   str(stats["total_events"]),    BLUE,  10),
            ("Authorized",     str(stats["allowed_devices"]), TEAL,  57),
            ("Blocked",        str(stats["blocked_devices"]), RED,  104),
            ("Critical Threats",str(stats["critical_threats"]),AMBER,151),
        ]
        y0 = pdf.get_y()
        for label, val, color, x in kpis:
            pdf.kpi_card(label, val, color, x, y0)
        pdf.ln(25)

        # Summary table
        pdf.set_font("Helvetica", "", 10)
        rows = [
            ("USB Connect Events",     stats["total_events"]),
            ("Total Devices Detected", stats["total_devices"]),
            ("Authorized Devices",     stats["allowed_devices"]),
            ("Blocked Devices",        stats["blocked_devices"]),
            ("Suspicious Devices",     stats["suspicious_devices"]),
            ("Security Violations",    stats["total_violations"]),
            ("File Operations Logged", stats["total_files"]),
            ("Critical Threat Devices",stats["critical_threats"]),
        ]
        for i, (k, v) in enumerate(rows):
            shade = (i % 2 == 0)
            pdf.set_fill_color(*(LGRAY if shade else WHITE))
            pdf.set_font("Helvetica", "B" if not shade else "", 9)
            pdf.cell(110, 6, "  " + k, fill=True)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, str(v), fill=True, ln=True)

        # Risk assessment
        pdf.ln(5)
        pdf.section_title("2.  Risk Assessment")
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*risk_color)
        pdf.cell(0, 8, f"  Overall Risk Level: {risk_label}", ln=True)
        pdf.set_text_color(0,0,0)
        pdf.set_font("Helvetica", "", 10)
        if risk_label == "HIGH RISK":
            pdf.multi_cell(0, 6, "  Critical: Unauthorized USB devices or critical threat scores "
                "detected. Immediate investigation and incident response required.")
        elif risk_label == "MEDIUM RISK":
            pdf.multi_cell(0, 6, "  Warning: High-risk devices detected. Review threat scores "
                "and violation logs. Consider temporary USB lockdown pending investigation.")
        else:
            pdf.multi_cell(0, 6, "  All detected devices appear authorized and within normal "
                "operational parameters. Continue routine monitoring.")

        # ── PAGE 3: CHARTS ─────────────────────────────────────────────
        pdf.add_page()
        pdf.section_title("3.  Security Analytics Charts")

        if chart_events and os.path.exists(chart_events):
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "  3.1  Event Types Distribution", ln=True)
            pdf.image(chart_events, x=10, w=180)
            pdf.ln(4)

        if chart_pie and os.path.exists(chart_pie):
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "  3.2  Device Status Breakdown", ln=True)
            pdf.image(chart_pie, x=50, w=110)
            pdf.ln(4)

        pdf.add_page()
        if chart_timeline and os.path.exists(chart_timeline):
            pdf.section_title("4.  Hourly Activity Timeline (Last 24 Hours)")
            pdf.image(chart_timeline, x=10, w=185)
            pdf.ln(4)

        # ── VIOLATIONS TABLE ───────────────────────────────────────────
        pdf.add_page()
        pdf.section_title("5.  Security Violations Log")
        if violations:
            cols = [("Timestamp",20),("Type",42),("Device",48),
                    ("Severity",20),("Action",40)]
            pdf.table_header(cols)
            for i, v in enumerate(violations[:30]):
                ts    = v.get("timestamp","")[:16]
                vtype = v.get("violation_type","")[:20]
                desc  = v.get("device_description","")[:24]
                sev   = v.get("severity","")
                act   = v.get("action_taken","")[:22]
                pdf.table_row([ts,vtype,desc,sev,act],
                              [20,42,48,20,40], shade=(i%2==0))
        else:
            pdf.set_font("Helvetica","I",10)
            pdf.cell(0,8,"  No violations recorded.",ln=True)

        # ── TOP THREATS TABLE ──────────────────────────────────────────
        pdf.section_title("6.  Top Threat Devices")
        if top_threats:
            cols = [("Device",60),("VID",20),("PID",20),
                    ("Score",20),("Level",25),("Connections",25)]
            pdf.table_header(cols)
            for i, d in enumerate(top_threats):
                pdf.table_row([
                    d.get("description","")[:30],
                    d.get("vendor_id",""),
                    d.get("product_id",""),
                    str(d.get("threat_score",0)),
                    d.get("threat_level",""),
                    str(d.get("total_connections",0)),
                ], [60,20,20,20,25,25], shade=(i%2==0))
        else:
            pdf.set_font("Helvetica","I",10)
            pdf.cell(0,8,"  No threat data recorded.",ln=True)

        # ── RECOMMENDATIONS ────────────────────────────────────────────
        pdf.add_page()
        pdf.section_title("7.  Recommendations")
        recs = [
            "Enforce this framework as a Windows Service for 24/7 persistent monitoring.",
            "Store audit logs centrally in a SIEM (Splunk, Elastic, Microsoft Sentinel).",
            "Apply Group Policy to restrict USB storage on all non-monitored endpoints.",
            "Conduct quarterly allowlist reviews -- remove stale or terminated-user devices.",
            "Cross-reference file SHA-256 hashes with VirusTotal for malware detection.",
            "Train employees annually on USB security risks and insider threat awareness.",
            "Implement role-based USB access control via Active Directory group membership.",
        ]
        if stats["blocked_devices"] > 0:
            recs.insert(0, f"URGENT: {stats['blocked_devices']} blocked device(s) detected. "
                           "Investigate immediately and file an incident report.")
        if stats["critical_threats"] > 0:
            recs.insert(0, f"CRITICAL: {stats['critical_threats']} device(s) scored CRITICAL. "
                           "These may be BadUSB or cloned hardware -- escalate to SOC.")

        for i, rec in enumerate(recs, 1):
            pdf.set_font("Helvetica", "B" if i <= 2 and "CRITICAL" in rec or "URGENT" in rec
                         else "", 9)
            pdf.set_text_color(*(RED if (i <= 2 and ("CRITICAL" in rec or "URGENT" in rec))
                                 else NAVY))
            pdf.set_x(12)
            pdf.multi_cell(0, 6, f"{i}. {rec}")
            pdf.ln(1)
        pdf.set_text_color(0,0,0)

        # Sign-off
        pdf.ln(10)
        pdf.set_draw_color(*BLUE)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)
        pdf.set_font("Helvetica","I",9)
        pdf.set_text_color(*MGRAY)
        pdf.cell(0,6,"This report was generated automatically by the USB Device Control & "
                 "Monitoring Framework v2.0. All data sourced from usb_security.db.",
                 align="C", ln=True)

        # ── Save ───────────────────────────────────────────────────────
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs(config.REPORT_DIR, exist_ok=True)
            output_path = os.path.join(config.REPORT_DIR,
                                       f"usb_audit_{ts}.pdf")

        pdf.output(output_path)
        return output_path
