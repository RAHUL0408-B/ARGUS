"""Build docs/ARGUS_Test_Report.pdf from data/e2e_results.json, data/unit_log.txt and UI screenshots.
Usage: python scripts/make_test_report.py [screenshot_dir]
"""
from __future__ import annotations
import json, platform, re, subprocess, sys
from collections import OrderedDict
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "docs" / "ARGUS_Test_Report.pdf"
SHOTS = Path(sys.argv[1]) if len(sys.argv) > 1 else None
NAVY, ACC, OK, BAD, MUT, LINE = colors.HexColor("#0f2742"), colors.HexColor("#1f6fb2"), colors.HexColor("#2e7d32"), colors.HexColor("#b3261e"), colors.HexColor("#5b6877"), colors.HexColor("#d9e0e8")

ss = {
    "title": ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=24, leading=29, textColor=NAVY, spaceAfter=6),
    "sub": ParagraphStyle("s", fontName="Helvetica", fontSize=12, leading=16, textColor=MUT),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY, spaceBefore=10, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=ACC, spaceBefore=8, spaceAfter=4),
    "b": ParagraphStyle("b", fontName="Helvetica", fontSize=9.5, leading=13),
    "c": ParagraphStyle("c", fontName="Helvetica", fontSize=7.8, leading=9.8),
    "cb": ParagraphStyle("cb", fontName="Helvetica-Bold", fontSize=7.8, leading=9.8),
    "big": ParagraphStyle("big", fontName="Helvetica-Bold", fontSize=30, leading=34, alignment=TA_CENTER),
    "cap": ParagraphStyle("cap", fontName="Helvetica", fontSize=8, leading=10, textColor=MUT, alignment=TA_CENTER),
}


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def P(t, st="b"):
    return Paragraph(t, ss[st])


def table(rows, widths, head=True, zebra=True, extra=None):
    t = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if head:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    if zebra:
        style += [("ROWBACKGROUNDS", (0, 1 if head else 0), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")])]
    t.setStyle(TableStyle(style + (extra or [])))
    return t


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as ex:
        return f"n/a ({ex.__class__.__name__})"


def env_info():
    nm = sh(["docker", "exec", "argus-tools", "nmap", "--version"]).splitlines()
    nk = sh(["docker", "exec", "argus-tools", "nikto", "-Version"])
    nkv = next((l for l in nk.splitlines() if "Nikto" in l and re.search(r"\d", l)), "Nikto (upstream git)")
    try:
        import urllib.request
        zv = json.load(urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:18090/JSON/core/view/version/", headers={"Host": "zap"}), timeout=5))["version"]
    except Exception:
        zv = "n/a"
    return [
        ["Operating system", f"{platform.system()} {platform.release()} ({platform.version()})"],
        ["Python", platform.python_version()],
        ["Docker", sh(["docker", "version", "--format", "{{.Server.Version}}"])],
        ["nmap (argus-tools)", nm[0] if nm else "n/a"],
        ["Nikto (argus-tools)", nkv.strip()[:80]],
        ["OWASP ZAP daemon", zv],
        ["Metasploit", sh(["docker", "image", "inspect", "--format", "{{index .RepoTags 0}} ({{.Created}})", "metasploitframework/metasploit-framework"])[:80]],
        ["Targets", "DVWA 10.77.0.10:80, OWASP Juice Shop 10.77.0.11:3000 (isolated network argus-lab_labnet 10.77.0.0/24)"],
        ["Git commit under test", sh(["git", "-C", str(ROOT), "log", "-1", "--format=%h %s"])],
        ["Planner mode", "rules-only (no ANTHROPIC_API_KEY available)"],
    ]


CRITERIA = [
    ("AI reasoning (20)", ["AI reasoning"]),
    ("End-to-end coverage (15)", ["Agent loop", "Coverage", "Planning", "Imports"]),
    ("Technical accuracy (15)", ["False positives", "Evidence"]),
    ("Correlation & false positives (15)", ["Correlation", "False positives"]),
    ("Risk prioritization (10)", ["Risk", "Attack paths"]),
    ("Safety & scope control (10)", ["Scope guard", "Safety", "Approvals", "Audit"]),
    ("Report quality (10)", ["Report", "Copilot"]),
    ("Efficiency & robustness (5)", ["Robustness", "Retest", "Platform"]),
]


def main():
    e2e = json.loads((DATA / "e2e_results.json").read_text())
    res = e2e["results"]
    unit_lines = (DATA / "unit_log.txt").read_text(errors="replace").splitlines()
    units = [(m.group(1), m.group(2), m.group(3)) for l in unit_lines if (m := re.match(r"tests/(\S+)::(\S+) (PASSED|FAILED|ERROR)", l))]
    u_pass = sum(1 for u in units if u[2] == "PASSED")
    e_pass = sum(r["pass"] for r in res)
    total, passed = len(res) + len(units), e_pass + u_pass
    fails = [r for r in res if not r["pass"]] + [{"area": "Unit", "name": u[1], "expected": "PASSED", "actual": u[2], "pass": False} for u in units if u[2] != "PASSED"]

    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="ARGUS Test Report", author="Team ARGUS")
    W = A4[0] - 32 * mm
    s = []

    # cover / summary
    s += [P("ARGUS - Full Test Report", "title"),
          P(f"AI-Powered Unified VAPT Agent &middot; DataOps Innovation Hackathon 2026, PS-1<br/>Test run: {esc(e2e['started'][:19].replace('T', ' '))} UTC to {esc(e2e['finished'][11:19])} UTC", "sub"),
          Spacer(1, 8)]
    verdict_col = OK if not fails else BAD
    tiles = [[P(f"<font color='{verdict_col.hexval().replace('0x', '#')}'>{passed}/{total}</font>", "big"), P(f"{u_pass}/{len(units)}", "big"), P(f"{e_pass}/{len(res)}", "big")],
             [P("checks passed overall", "cap"), P("automated unit tests (pytest)", "cap"), P("live end-to-end checks against the lab", "cap")]]
    s += [table(tiles, [W / 3] * 3, head=False, zebra=False, extra=[("BOX", (0, 0), (-1, -1), 0.8, LINE)]), Spacer(1, 8)]
    verdict = ("All checks passed. ARGUS ran a complete assessment against the live lab with real tools, enforced scope and approvals, removed false positives, "
               "and produced a full report with an intact audit trail." if not fails else
               f"{len(fails)} check(s) failed; they are listed in section 6 with the observed behaviour.")
    s += [P(f"<b>Verdict:</b> {esc(verdict)}"), Spacer(1, 6)]

    s += [P("1. Results by area", "h1")]
    areas = OrderedDict()
    for r in res:
        a = areas.setdefault(r["area"], [0, 0]); a[0] += r["pass"]; a[1] += 1
    rows = [["Area", "Passed", "Total", "Result"]] + [[a, str(p), str(t), "PASS" if p == t else "FAIL"] for a, (p, t) in areas.items()]
    rows.append(["Unit tests (pytest)", str(u_pass), str(len(units)), "PASS" if u_pass == len(units) else "FAIL"])
    ex = [("TEXTCOLOR", (3, i), (3, i), OK if rows[i][3] == "PASS" else BAD) for i in range(1, len(rows))]
    s += [table(rows, [W * .5, W * .15, W * .15, W * .2], extra=ex + [("FONTNAME", (3, 1), (3, -1), "Helvetica-Bold")])]

    s += [P("2. Coverage of the judging criteria", "h1"),
          P("Each criterion is mapped to the test areas that exercise it. All counts are from this run.")]
    rows = [["Criterion (points)", "Evidence from this test run", "Checks"]]
    for crit, ar in CRITERIA:
        rr = [r for r in res if r["area"] in ar]
        names = "; ".join(r["name"] for r in rr[:5]) + (" ..." if len(rr) > 5 else "")
        rows.append([P(esc(crit), "cb"), P(esc(names), "c"), P(f"{sum(r['pass'] for r in rr)}/{len(rr)}", "cb")])
    s += [table(rows, [W * .25, W * .63, W * .12])]

    ctx, tm = e2e.get("context", {}), e2e.get("timings", {})
    s += [P("3. Key measurements", "h1")]
    rows = [["Measurement", "Value"]]
    rows += [[k, f"{v:.0f} s" if v >= 1 else f"{v:.2f} s"] for k, v in tm.items()]
    if ctx:
        rows += [["Findings after autonomous phase", str(ctx.get("findings_auto", "-"))],
                 ["Proof level of those findings", ", ".join(f"{k} {v}" for k, v in ctx.get("status_counts", {}).items())],
                 ["Pages in generated report", str(ctx.get("report_pages", "-"))],
                 ["Audit entries for the assessment", str(ctx.get("audit_entries", "-"))],
                 ["Main assessment id", ctx.get("aid", "-")]]
    s += [table(rows, [W * .5, W * .5])]

    s += [PageBreak(), P("4. Test environment", "h1"), table([["Item", "Value"]] + [[a, P(esc(b), "c")] for a, b in env_info()], [W * .28, W * .72])]
    s += [P("Method", "h2"),
          P("<b>Unit tests</b> (backend/tests, pytest) cover the scope guard, audit chain tamper detection, every parser, correlation, confidence, risk, grounding, "
            "HTTP validators and the PDF builder, using small hand-written inputs. <b>Live end-to-end tests</b> (scripts/e2e_live.py) drive the running server through "
            "its public HTTP API exactly as the UI does, against the real lab containers: they create assessments, approve plans, decide approvals, import files, "
            "retest, ask the copilot, download the report, press the kill switch, tamper with evidence, and stop the ZAP container to test failure handling. "
            "Every check records the expected and the actual value; nothing is mocked in the live suite.")]

    s += [PageBreak(), P("5. Live end-to-end checks (detail)", "h1")]
    for area in areas:
        rows = [["#", "Check", "Expected", "Actual", "Result"]]
        rr = [r for r in res if r["area"] == area]
        for i, r in enumerate(rr, 1):
            rows.append([str(i), P(esc(r["name"]), "c"), P(esc(r["expected"])[:200], "c"), P(esc(r["actual"])[:300], "c"), P(f"<font color='{'#2e7d32' if r['pass'] else '#b3261e'}'><b>{'PASS' if r['pass'] else 'FAIL'}</b></font>", "c")])
        s += [KeepTogether([P(esc(area), "h2"), table(rows, [W * .05, W * .29, W * .2, W * .36, W * .1])])] if len(rr) < 9 else [P(esc(area), "h2"), table(rows, [W * .05, W * .29, W * .2, W * .36, W * .1])]

    s += [PageBreak(), P("6. Automated unit tests", "h1")]
    rows = [["File", "Test", "Result"]] + [[f, P(esc(n), "c"), P(f"<font color='{'#2e7d32' if r == 'PASSED' else '#b3261e'}'><b>{r}</b></font>", "c")] for f, n, r in units]
    s += [table(rows, [W * .25, W * .6, W * .15])]

    s += [P("7. Failures and defects", "h1")]
    if fails:
        rows = [["Area", "Check", "Expected", "Actual"]] + [[r["area"], P(esc(r["name"]), "c"), P(esc(r["expected"]), "c"), P(esc(r["actual"]), "c")] for r in fails]
        s += [table(rows, [W * .15, W * .3, W * .2, W * .35])]
    else:
        s += [P("No check failed in this run.")]
    s += [P("Known limitations (not defects, documented in docs/INTEGRATIONS.md)", "h2")]
    for t in ["Nessus, Burp and OpenVAS are Import-only. The sample files used here are synthetic inputs written by the team, labelled SAMPLE-, and are not real scanner output.",
              "The optional Claude planner was not tested because no API key was available; every run used the deterministic rule planner.",
              "The CISA KEV list is a partial offline snapshot; the CVE hint table for version matching is small.",
              "ZAP active scan is capped at 4 minutes and alert fetch at 500 alerts, so active-scan coverage may be partial.",
              "Only web targets were available in the lab; SSH/FTP adapters and Metasploit ssh/ftp banner modules were not exercised live.",
              "Tests were run on a single Windows machine against the team's own Docker lab, not the organizer lab."]:
        s += [P("&bull; " + esc(t))]

    if SHOTS and SHOTS.exists():
        s += [PageBreak(), P("8. User interface checks", "h1"),
              P("Screenshots captured with headless Microsoft Edge from the running server after the test run (same data the API returned).")]
        for name, cap in [("ui_welcome", "Start page for new users"), ("ui_overview", "Overview dashboard"), ("ui_findings", "Findings with filters and proof level"),
                          ("ui_plan", "Plan and agent reasoning (decision cards)"), ("ui_graph", "Attack-path graph"), ("ui_approvals", "Approvals with analyst decisions"),
                          ("ui_report", "Report download and audit trail"), ("ui_matrix", "Runtime integration matrix")]:
            p = SHOTS / f"{name}.png"
            if p.exists():
                img = Image(str(p)); r = img.imageHeight / img.imageWidth
                img.drawWidth, img.drawHeight = W, W * r
                if img.drawHeight > 115 * mm:
                    img.drawHeight, img.drawWidth = 115 * mm, 115 * mm / r
                s += [KeepTogether([img, P(cap, "cap"), Spacer(1, 6)])]

    s += [PageBreak(), P("9. How to reproduce", "h1"),
          P("1. <font face='Courier'>.\\scripts\\start.ps1</font> (lab + server on http://localhost:8765)<br/>"
            "2. <font face='Courier'>cd backend; python -m pytest -v &gt; ..\\data\\unit_log.txt</font><br/>"
            "3. <font face='Courier'>python scripts\\e2e_live.py</font> (about 15-20 minutes; stops and restarts the argus-zap container during the resilience test)<br/>"
            "4. <font face='Courier'>python scripts\\make_test_report.py [screenshot folder]</font>"),
          Spacer(1, 6), P("Raw results: data/e2e_results.json (git-ignored). This report was generated from those files; no value in it was typed by hand.", "c")]

    def page(c, d):
        c.saveState(); c.setFont("Helvetica", 7.5); c.setFillColor(MUT)
        c.drawString(16 * mm, 9 * mm, "ARGUS test report - lab-only testing, authorized targets")
        c.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {d.page}"); c.restoreState()

    doc.build(s, onFirstPage=page, onLaterPages=page)
    print(f"wrote {OUT} ({passed}/{total} passed)")


if __name__ == "__main__":
    main()
