"""Structured HTML, JSON and PDF reports for saved analyses, discovery records and change assessments.

Reports are built from stored snapshots, which never contain passwords, SNMP passphrases or community strings.
"""
from __future__ import annotations

import html
import io
import json
from datetime import datetime


def _text(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(v) for v in value) or "—"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {_text(v)}" for k, v in value.items())
    return str(value)


def _table(columns: list[str], rows: list[list]) -> dict:
    return {"columns": columns, "rows": [[_text(c) for c in row] for row in rows]}


def from_history(record, snapshot: dict | None = None) -> dict:
    """snapshot: the credential-free copy returned by history_service.to_out."""
    snapshot = snapshot if snapshot is not None else (record.snapshot or {})
    summary = record.summary or {}
    sections = []
    meta = [("Network", record.network_name), ("Record", record.kind), ("Created", record.created_at),
            ("Created by", record.creator.username if record.creator else None)]
    analysis = snapshot.get("analysis")
    if analysis:
        sections.append({"heading": "Summary", "table": _table(["Measure", "Value"], [
            ["Status", analysis.get("status")], ["Issues", analysis.get("issue_count")],
            ["Security and hygiene advisories", analysis.get("advisory_count")],
            ["Devices checked", analysis.get("devices_checked")], ["Links checked", analysis.get("links_checked")],
            ["Failing required flows", analysis.get("failing_flow_count")]])})
        issues = analysis.get("issues", [])
        if issues:
            sections.append({"heading": "Findings (highest risk first)", "table": _table(
                ["Rule", "Pack", "Severity", "Risk (S/I/E)", "Root cause", "Recommendation"],
                [[f"{i['rule_id']} {i.get('name', '')}", i.get("pack"), i.get("severity"),
                  f"{(i.get('risk') or {}).get('score', '—')} ({(i.get('risk') or {}).get('S', '—')}/"
                  f"{(i.get('risk') or {}).get('I', '—')}/{(i.get('risk') or {}).get('E', '—')})",
                  i.get("root_cause") or i.get("message"), i.get("recommendation")] for i in issues])})
        flows = analysis.get("flows", [])
        if flows:
            sections.append({"heading": "Traffic intents", "table": _table(
                ["Intent", "Source", "Destination", "Expected", "Result", "Reason"],
                [[f.get("name"), f.get("source"), f.get("destination"), f.get("expected"),
                  "PASS" if f.get("ok") else "UNKNOWN" if f.get("ok") is None else "FAIL", f.get("reason")] for f in flows])})
        advisories = analysis.get("advisories", [])
        if advisories:
            sections.append({"heading": "Security hygiene advisories", "table": _table(
                ["Rule", "Devices", "Evidence", "Recommendation", "Reference"],
                [[f"{a['rule_id']} {a.get('title', '')}", a.get("devices"),
                  " ".join(e.get("detail", "") for e in a.get("evidence", [])), a.get("recommendation"), a.get("reference")]
                 for a in advisories])})
        gaps = analysis.get("gaps") or analysis.get("coverage_notes") or []
        if gaps:
            sections.append({"heading": "Coverage and evidence gaps",
                             "paragraphs": [g.get("detail", "") + (" " + g.get("next_step", "") if g.get("next_step") else "")
                                            if isinstance(g, dict) else str(g) for g in gaps]})
    else:
        sections.append({"heading": "Summary", "table": _table(["Item", "Value"], [[k.replace("_", " ").capitalize(), v]
                                                                                    for k, v in summary.items()])})
        for key, value in snapshot.items():
            if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                columns = list(dict.fromkeys(k for v in value[:50] for k in v if not isinstance(v.get(k), (dict, list))))[:7]
                if columns:
                    sections.append({"heading": key.replace("_", " ").capitalize(), "table": _table(
                        [c.replace("_", " ").capitalize() for c in columns], [[v.get(c) for c in columns] for v in value[:200]])})
            elif isinstance(value, list) and value:
                sections.append({"heading": key.replace("_", " ").capitalize(), "paragraphs": [_text(v) for v in value[:200]]})
            elif isinstance(value, (str, int, float)) and value not in ("", None):
                sections.append({"heading": key.replace("_", " ").capitalize(), "paragraphs": [_text(value)]})
    return {"title": record.title, "meta": meta, "sections": sections,
            "footer": "NetGuard report. Snapshots never contain passwords, SNMP passphrases or community strings."}


def from_assessment(a) -> dict:
    change = a.change or {}
    factors = a.risk_factors or {}
    formula = (f"100 x {factors.get('S')} x (1 + {factors.get('I')} + {factors.get('E')}) / 24 = {a.total_risk_score}"
               if factors else f"{a.total_risk_score}/100")
    sections = [
        {"heading": "Proposed change", "table": _table(["Item", "Value"], [
            ["Device", change.get("device")], ["Target", change.get("target")], ["Change", change.get("change_type_label")],
            ["Current", change.get("current_value")], ["Proposed", change.get("proposed_value")], ["Reason", change.get("reason")],
            ["Status", change.get("status")]])},
        {"heading": "Decision", "table": _table(["Item", "Value"], [
            ["Recommendation", a.recommendation_label], ["Risk", f"{a.risk_level} ({formula})"],
            ["Evidence confidence", (a.evidence_confidence or "—").title()], ["Validation", a.validation_result],
            ["Summary", a.recommendation_summary]])},
    ]
    if a.findings:
        sections.append({"heading": "Findings introduced by the change", "table": _table(
            ["Rule", "Severity", "Risk", "Root cause", "Recommendation"],
            [[f"{f['rule_id']} {f.get('name', '')}", f.get("severity"), (f.get("risk") or {}).get("score"),
              f.get("root_cause") or f.get("message"), f.get("recommendation")] for f in a.findings])})
    impacts = [i for i in a.impacts if i.affected]
    if impacts:
        sections.append({"heading": "Affected traffic", "table": _table(
            ["Flow", "Source", "Destination", "Before", "After", "Explanation"],
            [[i.service, i.source_device, i.destination_device, i.baseline_status, i.candidate_status, i.explanation]
             for i in impacts])})
    commands = change.get("commands") or []
    if commands:
        sections.append({"heading": "Generated commands", "code": "\n".join(commands)})
    if a.explanation:
        sections.append({"heading": "Explanation", "paragraphs": a.explanation.split("\n\n")})
    sections.append({"heading": "Evidence scope", "paragraphs": [a.evidence_scope]})
    return {"title": f"Change assessment #{a.id}: {change.get('device', '')} {change.get('change_type_label', '')}",
            "meta": [("Network", a.network_name), ("Analysed", a.created_at), ("Analysed by", a.created_by_username)],
            "sections": sections, "footer": "NetGuard change assessment. The analysis ran on a copy of the network model."}


_CSS = """body{font-family:Arial,Helvetica,sans-serif;color:#111;margin:32px;font-size:12px}h1{font-size:20px;margin:0 0 4px}
h2{font-size:14px;margin:22px 0 6px;border-bottom:1px solid #999;padding-bottom:2px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eee}.meta{color:#444;margin-bottom:10px}
pre{background:#f4f4f4;border:1px solid #ccc;padding:8px;white-space:pre-wrap}footer{margin-top:24px;color:#555;font-size:11px}"""


def render_html(doc: dict) -> str:
    e = html.escape
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>{e(doc['title'])}</title><style>{_CSS}</style></head><body>",
             f"<h1>{e(doc['title'])}</h1><div class='meta'>" +
             " · ".join(f"{e(k)}: {e(_text(v))}" for k, v in doc["meta"]) + "</div>"]
    for section in doc["sections"]:
        parts.append(f"<h2>{e(section['heading'])}</h2>")
        for paragraph in section.get("paragraphs", []):
            parts.append(f"<p>{e(paragraph)}</p>")
        if section.get("code"):
            parts.append(f"<pre>{e(section['code'])}</pre>")
        table = section.get("table")
        if table:
            parts.append("<table><tr>" + "".join(f"<th>{e(c)}</th>" for c in table["columns"]) + "</tr>" +
                         "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in table["rows"]) +
                         "</table>")
    parts.append(f"<footer>{e(doc['footer'])} Generated {datetime.now().strftime('%d %b %Y %H:%M')}.</footer></body></html>")
    return "".join(parts)


def render_pdf(doc: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = styles["BodyText"].clone("ng-body", fontName="Helvetica", fontSize=8, leading=10)
    cell = styles["BodyText"].clone("ng-cell", fontName="Helvetica", fontSize=7, leading=9)
    head = styles["Heading2"].clone("ng-h2", fontName="Helvetica-Bold", fontSize=11, spaceBefore=8, spaceAfter=4)
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm,
                            bottomMargin=12 * mm, title=doc["title"], author="NetGuard")
    e = html.escape
    story = [Paragraph(e(doc["title"]), styles["Title"].clone("ng-title", fontName="Helvetica-Bold", fontSize=15)),
             Paragraph(e(" · ".join(f"{k}: {_text(v)}" for k, v in doc["meta"])), body), Spacer(1, 4)]
    width = pdf.width
    for section in doc["sections"]:
        story.append(Paragraph(e(section["heading"]), head))
        for paragraph in section.get("paragraphs", []):
            story.append(Paragraph(e(paragraph), body))
        if section.get("code"):
            story.append(Preformatted(section["code"], cell.clone("ng-code", fontName="Courier")))
        table = section.get("table")
        if table:
            rows = [[Paragraph(f"<b>{e(c)}</b>", cell) for c in table["columns"]]] + \
                   [[Paragraph(e(c), cell) for c in row] for row in table["rows"]]
            t = Table(rows, colWidths=[width / len(table["columns"])] * len(table["columns"]), repeatRows=1)
            t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(t)
    story += [Spacer(1, 8), Paragraph(e(doc["footer"]), body)]
    pdf.build(story)
    return buffer.getvalue()


def response(doc: dict, fmt: str, filename: str, raw: dict | None = None):
    from fastapi import Response

    if fmt == "html":
        return Response(render_html(doc), media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{filename}.html"'})
    if fmt == "pdf":
        return Response(render_pdf(doc), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'})
    return Response(json.dumps(raw if raw is not None else doc, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{filename}.json"'})
