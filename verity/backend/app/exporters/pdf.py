"""
PDF exporter for Verity scan results.
Uses WeasyPrint to render an HTML report to a PDF byte string.
"""

from typing import Any


_GREEN = "#93cb52"
_TEAL = "#1c9770"
_LIGHT_TEAL = "#bef3e2"
_LIGHT_RED = "#f2eeee"
_LIGHT_AMBER = "#fff8e1"
_DARK_GRAY = "#464646"

_RISK_COLORS: dict[str, tuple[str, str]] = {
    "LOW": (_GREEN, "#ffffff"),
    "MEDIUM": ("#f5a623", "#ffffff"),
    "HIGH": ("#e8682a", "#ffffff"),
    "CRITICAL": ("#c0392b", "#ffffff"),
    "UNKNOWN": ("#888888", "#ffffff"),
}

_GRADE_COLORS: dict[str, str] = {
    "A": _GREEN,
    "B": "#5ab4ac",
    "C": "#f5a623",
    "D": "#e8682a",
    "F": "#c0392b",
}


def export_pdf(scan_detail: dict) -> bytes:
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise ImportError(
            "WeasyPrint is required for PDF export. "
            "Install it with: pip install weasyprint"
        ) from exc

    html_content = _build_html(scan_detail)
    try:
        pdf_bytes = HTML(string=html_content).write_pdf()
    except Exception as exc:
        raise RuntimeError(f"PDF rendering failed: {exc}") from exc

    return pdf_bytes


def _esc(value: Any) -> str:
    text = str(value) if value is not None else ""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _risk_badge(level: str) -> str:
    bg, fg = _RISK_COLORS.get(str(level).upper(), ("#888888", "#ffffff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:4px;font-weight:bold;font-size:0.85em;">'
        f"{_esc(level)}</span>"
    )


def _grade_badge(grade: str) -> str:
    color = _GRADE_COLORS.get(str(grade).upper(), "#888888")
    return (
        f'<span style="background:{color};color:#ffffff;padding:2px 8px;'
        f'border-radius:4px;font-weight:bold;font-size:0.85em;">{_esc(grade)}</span>'
    )


def _pass_fail_badge(ok: bool, partial: bool = False) -> str:
    if ok:
        return '<span style="background:#93cb52;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">PASS</span>'
    if partial:
        return '<span style="background:#f5a623;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">PARTIAL</span>'
    return '<span style="background:#c0392b;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.85em;">FAIL</span>'


def _score_bar(score: float, max_score: float = 10.0) -> str:
    pct = min(100.0, score / max_score * 100)
    if pct >= 80:
        color = _GREEN
    elif pct >= 60:
        color = "#f5a623"
    else:
        color = "#c0392b"
    return (
        f'<div style="display:flex;align-items:center;gap:6px;">'
        f'<div style="flex:1;background:#e5e7eb;border-radius:4px;height:8px;">'
        f'<div style="width:{pct:.1f}%;background:{color};border-radius:4px;height:8px;"></div>'
        f'</div>'
        f'<span style="font-size:0.8em;color:{_DARK_GRAY};min-width:30px;text-align:right;">{score:.1f}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_cover(scan: dict) -> str:
    filename = _esc(scan.get("filename", "Unknown"))
    created_at = _esc(scan.get("created_at", ""))
    sbom_format = _esc(scan.get("sbom_format", ""))
    format_version = _esc(scan.get("format_version") or "")
    risk_level = str(scan.get("risk_level", "UNKNOWN")).upper()
    risk_score = scan.get("risk_score", 0.0)
    quality = scan.get("quality") or {}
    q_score = quality.get("overall_score")
    q_grade = quality.get("grade") or ""
    ntia = scan.get("ntia_compliant", False)
    total = scan.get("total_components", 0)
    vulnerable = scan.get("vulnerable_components", 0)

    ntia_badge = _pass_fail_badge(ntia)
    q_section = (
        f'<tr><td>Quality Score</td>'
        f'<td><strong>{q_score:.1f}</strong> &nbsp; {_grade_badge(q_grade)}</td></tr>'
    ) if q_score is not None else ""

    return f"""
    <div class="cover-page">
      <div class="cover-header">
        <div class="cover-logo">Verity</div>
        <div class="cover-title">SBOM Compliance Report</div>
        <div class="cover-subtitle">{filename}</div>
      </div>
      <div class="cover-meta">
        <table class="cover-table">
          <tr><td>Scan Date</td><td>{created_at}</td></tr>
          <tr><td>Format</td><td>{sbom_format} {format_version}</td></tr>
          <tr><td>Total Components</td><td>{total}</td></tr>
          <tr><td>Vulnerable Components</td><td>{vulnerable}</td></tr>
          <tr><td>Risk Level</td><td>{_risk_badge(risk_level)} &nbsp; Score: <strong>{risk_score:.2f}</strong></td></tr>
          {q_section}
          <tr><td>NTIA Compliant</td><td>{ntia_badge}</td></tr>
        </table>
      </div>
    </div>
    <div class="page-break"></div>
"""


def _build_executive_summary(scan: dict) -> str:
    quality = scan.get("quality") or {}
    categories = quality.get("categories") or []

    if not categories:
        return ""

    cat_rows = ""
    for cat in categories:
        name = _esc(cat.get("name", ""))
        score = cat.get("score", 0.0)
        weight = cat.get("weight", 0)
        cat_rows += (
            f"<tr>"
            f'<td style="font-weight:500;">{name}</td>'
            f'<td style="width:50%;">{_score_bar(score)}</td>'
            f'<td style="text-align:center;">{weight}</td>'
            f"</tr>\n"
        )

    # Top risk factors: categories with score < 6
    risk_factors = sorted(
        [c for c in categories if c.get("score", 10) < 6.0],
        key=lambda c: c.get("score", 10),
    )[:3]

    risk_items = ""
    for rf in risk_factors:
        risk_items += f'<li><strong>{_esc(rf.get("name",""))}</strong> — score {rf.get("score",0):.1f}/10</li>'

    # Recommendations: look at failing features
    recs: list[str] = []
    for cat in categories:
        for feat in (cat.get("features") or []):
            if feat.get("applicable") and feat.get("score", 10) < 5.0 and len(recs) < 3:
                recs.append(feat.get("detail", feat.get("key", "")))

    rec_items = "".join(f"<li>{_esc(r)}</li>" for r in recs) if recs else "<li>No critical issues detected.</li>"

    return f"""
    <div class="section-title">Executive Summary — Quality Score Categories</div>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Score</th>
          <th>Weight</th>
        </tr>
      </thead>
      <tbody>
        {cat_rows}
      </tbody>
    </table>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0;">
      <div class="info-box" style="background:{_LIGHT_RED};">
        <div class="info-box-title" style="color:#c0392b;">Top Risk Factors</div>
        <ul style="margin:4px 0 0 0;padding-left:18px;">
          {risk_items if risk_items else '<li>No critical categories below threshold.</li>'}
        </ul>
      </div>
      <div class="info-box" style="background:{_LIGHT_TEAL};">
        <div class="info-box-title" style="color:{_TEAL};">Recommended Actions</div>
        <ul style="margin:4px 0 0 0;padding-left:18px;">
          {rec_items}
        </ul>
      </div>
    </div>
"""


def _build_compliance_section(scan: dict) -> str:
    compliance = scan.get("compliance") or {}
    if not compliance:
        return ""

    rows = ""

    ntia = compliance.get("ntia") or {}
    if ntia:
        ok = ntia.get("overall_compliant", False)
        score = ntia.get("overall_score", 0.0)
        elements = ntia.get("elements") or []
        passing = sum(1 for e in elements if e.get("compliant"))
        rows += (
            f"<tr>"
            f'<td><strong>NTIA Minimum Elements</strong></td>'
            f"<td>{_pass_fail_badge(ok)}</td>"
            f'<td style="text-align:center;">{score:.1f}/10</td>'
            f'<td>{passing}/{len(elements)} elements pass</td>'
            f"</tr>\n"
        )
        for elem in elements:
            elem_ok = elem.get("compliant", False)
            fail_count = len(elem.get("failing_components") or [])
            detail = _esc(elem.get("detail", ""))
            rows += (
                f'<tr style="background:#f9f9f9;font-size:0.88em;">'
                f'<td style="padding-left:24px;color:#666;">{_esc(elem.get("element_name",""))}</td>'
                f"<td>{_pass_fail_badge(elem_ok)}</td>"
                f'<td></td>'
                f'<td style="color:#888;">{detail}{" (" + str(fail_count) + " components failing)" if fail_count else ""}</td>'
                f"</tr>\n"
            )

    for key, label in [("bsi_v21", "BSI TR-03183-2 v2.1"), ("fsct", "FSCT v3"), ("oct", "OpenChain Telco v1.1")]:
        std = compliance.get(key) or {}
        if not std:
            continue
        score = std.get("overall_score", 0.0)
        if key == "bsi_v21":
            ok = std.get("compliant", False)
            req_p = std.get("required_passed", 0)
            req_t = std.get("required_total", 0)
            add_p = std.get("additional_passed", 0)
            add_t = std.get("additional_total", 0)
            detail = f"SHALL: {req_p}/{req_t} &nbsp;|&nbsp; SHOULD: {add_p}/{add_t}"
            partial = (not ok) and req_p > 0
        elif key == "oct":
            spdx_fail = std.get("spdx_only_fail", False)
            ok = score >= 8.0 and not spdx_fail
            partial = (not ok) and score >= 5.0
            detail = "Requires SPDX format" if spdx_fail else f"Score {score:.1f}/10"
        else:
            ok = score >= 8.0
            partial = (not ok) and score >= 5.0
            detail = f"Score {score:.1f}/10"
        rows += (
            f"<tr>"
            f'<td><strong>{_esc(label)}</strong></td>'
            f"<td>{_pass_fail_badge(ok, partial)}</td>"
            f'<td style="text-align:center;">{score:.1f}/10</td>'
            f"<td>{detail}</td>"
            f"</tr>\n"
        )

    if not rows:
        return ""

    return f"""
    <div class="section-title">Compliance Status</div>
    <table>
      <thead>
        <tr>
          <th>Standard</th>
          <th>Result</th>
          <th>Score</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
"""


def _build_vulnerability_section(scan: dict) -> str:
    components = scan.get("components") or []
    all_vulns: list[tuple[str, dict]] = []
    for comp in components:
        for vuln in (comp.get("vulnerabilities") or []):
            all_vulns.append((comp.get("name", ""), vuln))

    if not all_vulns:
        return ""

    # Sort by EPSS desc, then CVSS desc
    all_vulns.sort(
        key=lambda x: (-(x[1].get("epss_score") or 0.0), -(x[1].get("cvss_score") or 0.0))
    )

    kev_count = sum(1 for _, v in all_vulns if v.get("in_kev"))
    high_epss_count = sum(1 for _, v in all_vulns if (v.get("epss_score") or 0) > 0.5)

    banner = ""
    if kev_count:
        banner = (
            f'<div style="background:{_LIGHT_RED};border-left:4px solid #c0392b;padding:8px 12px;'
            f'border-radius:4px;margin-bottom:12px;font-size:0.9em;">'
            f'<strong>{kev_count} CVE(s) are in the CISA KEV catalog</strong> — active exploitation confirmed. Remediate immediately.</div>'
        )

    rows = ""
    for comp_name, vuln in all_vulns[:50]:  # cap at 50 rows for PDF size
        vid = _esc(vuln.get("id", ""))
        severity = str(vuln.get("severity", "")).upper()
        cvss = vuln.get("cvss_score", 0.0)
        epss = vuln.get("epss_score")
        epss_pct = vuln.get("epss_percentile")
        in_kev = vuln.get("in_kev", False)
        fixed = _esc(vuln.get("fixed_version") or "")

        epss_cell = f"{epss:.3f} ({epss_pct:.0f}th%)" if epss is not None and epss_pct is not None else "N/A"
        kev_cell = (
            '<span style="background:#c0392b;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.8em;font-weight:bold;">KEV</span>'
            if in_kev else ""
        )
        row_bg = _LIGHT_RED if in_kev else ("#fff8e1" if (epss or 0) > 0.5 else "#ffffff")

        rows += (
            f'<tr style="background:{row_bg};">'
            f"<td>{vid}</td>"
            f"<td>{_esc(comp_name)}</td>"
            f"<td>{_risk_badge(severity)}</td>"
            f'<td style="text-align:center;">{cvss:.1f}</td>'
            f'<td style="text-align:center;">{epss_cell}</td>'
            f'<td style="text-align:center;">{kev_cell}</td>'
            f'<td style="font-size:0.85em;color:#888;">{fixed or "—"}</td>'
            f"</tr>\n"
        )

    if not rows:
        return ""

    truncation_note = (
        f'<p style="font-size:0.8em;color:#888;margin-top:4px;">Showing top 50 of {len(all_vulns)} vulnerabilities. Export JSON for full list.</p>'
        if len(all_vulns) > 50 else ""
    )

    return f"""
    <div class="section-title">Vulnerability Summary ({len(all_vulns)} total, {kev_count} KEV, {high_epss_count} high-EPSS)</div>
    {banner}
    <table>
      <thead>
        <tr>
          <th>CVE / ID</th>
          <th>Component</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>EPSS (percentile)</th>
          <th>KEV</th>
          <th>Fixed In</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
    {truncation_note}
"""


def _build_component_section(scan: dict) -> str:
    components = sorted(
        (scan.get("components") or []),
        key=lambda c: c.get("risk_score", 0.0),
        reverse=True,
    )
    if not components:
        return ""

    rows = ""
    for comp in components:
        name = _esc(comp.get("name", ""))
        version = _esc(comp.get("version") or "—")
        supplier = _esc(comp.get("supplier") or "—")
        purl = _esc(comp.get("purl") or "—")
        licenses = _esc(", ".join(comp.get("licenses") or []) or "—")
        risk = str(comp.get("risk_level", "")).upper()
        score = comp.get("risk_score", 0.0)
        vuln_count = len(comp.get("vulnerabilities") or [])
        rows += (
            f"<tr>"
            f"<td>{name}</td>"
            f"<td>{version}</td>"
            f"<td>{supplier}</td>"
            f'<td style="font-size:0.8em;color:#666;max-width:180px;word-break:break-all;">{purl}</td>'
            f"<td>{licenses}</td>"
            f"<td>{_risk_badge(risk)}</td>"
            f'<td style="text-align:center;">{score:.1f}</td>'
            f'<td style="text-align:center;">{vuln_count if vuln_count else "—"}</td>'
            f"</tr>\n"
        )

    return f"""
    <div class="section-title">Component Risk Table ({len(components)} components)</div>
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Version</th>
          <th>Supplier</th>
          <th>PURL</th>
          <th>Licenses</th>
          <th>Risk</th>
          <th>Score</th>
          <th>Vulns</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
"""


def _build_issues_section(scan: dict) -> str:
    issues = scan.get("validation_issues") or []
    if not issues:
        return ""

    rows = ""
    for issue in issues:
        sev = _esc(issue.get("severity", ""))
        code = _esc(issue.get("code", ""))
        msg = _esc(issue.get("message", ""))
        comp = _esc(issue.get("component_name") or "—")
        row_bg = _LIGHT_RED if sev == "ERROR" else ("#fff8e1" if sev == "WARNING" else "#ffffff")
        rows += (
            f'<tr style="background:{row_bg};">'
            f"<td>{sev}</td><td><code>{code}</code></td><td>{msg}</td><td>{comp}</td>"
            f"</tr>\n"
        )

    return f"""
    <div class="section-title">Validation Issues ({len(issues)})</div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Code</th>
          <th>Message</th>
          <th>Component</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
"""


# ---------------------------------------------------------------------------
# Main HTML builder
# ---------------------------------------------------------------------------

def _build_html(scan: dict) -> str:
    filename = _esc(scan.get("filename", "Unknown"))

    cover = _build_cover(scan)
    exec_summary = _build_executive_summary(scan)
    compliance_section = _build_compliance_section(scan)
    vuln_section = _build_vulnerability_section(scan)
    component_section = _build_component_section(scan)
    issues_section = _build_issues_section(scan)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Verity SBOM Report — {filename}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    color: {_DARK_GRAY};
    margin: 0;
    padding: 0;
    font-size: 12px;
    line-height: 1.5;
  }}

  /* Cover page */
  .cover-page {{
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 60px 48px;
  }}
  .cover-header {{
    border-left: 6px solid {_TEAL};
    padding-left: 24px;
    margin-bottom: 40px;
  }}
  .cover-logo {{
    font-size: 2em;
    font-weight: 900;
    color: {_TEAL};
    letter-spacing: 0.05em;
    margin-bottom: 8px;
  }}
  .cover-title {{
    font-size: 1.6em;
    font-weight: 700;
    color: {_DARK_GRAY};
    margin-bottom: 6px;
  }}
  .cover-subtitle {{
    font-size: 1.1em;
    color: #666;
    word-break: break-all;
  }}
  .cover-table {{
    border-collapse: collapse;
    width: 100%;
    max-width: 500px;
  }}
  .cover-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid #eee;
    vertical-align: middle;
  }}
  .cover-table td:first-child {{
    color: #888;
    font-size: 0.9em;
    width: 180px;
  }}

  /* Content */
  .content {{ padding: 32px 48px; }}
  .section-title {{
    color: {_TEAL};
    font-size: 1.05em;
    font-weight: 700;
    margin: 28px 0 10px 0;
    border-bottom: 2px solid {_LIGHT_TEAL};
    padding-bottom: 4px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 12px;
    font-size: 0.88em;
  }}
  th {{
    background: {_LIGHT_TEAL};
    color: {_DARK_GRAY};
    padding: 7px 10px;
    text-align: left;
    font-weight: 700;
    font-size: 0.85em;
  }}
  td {{
    padding: 6px 10px;
    border-bottom: 1px solid #eeeeee;
    vertical-align: middle;
  }}
  tr:nth-child(even) td {{ background: #f9f9f9; }}
  code {{
    font-family: monospace;
    font-size: 0.9em;
    background: #f3f4f6;
    padding: 1px 4px;
    border-radius: 3px;
  }}
  .info-box {{
    padding: 12px 14px;
    border-radius: 6px;
    font-size: 0.88em;
  }}
  .info-box-title {{
    font-weight: 700;
    margin-bottom: 4px;
  }}
  .page-break {{ page-break-after: always; }}
  .footer {{
    text-align: center;
    color: #aaa;
    font-size: 0.8em;
    margin-top: 40px;
    padding: 16px 0;
    border-top: 1px solid #eee;
  }}
  @page {{ margin: 1.5cm; }}
</style>
</head>
<body>
{cover}
<div class="content">
{exec_summary}
{compliance_section}
{vuln_section}
{component_section}
{issues_section}
</div>
<div class="footer">
  Generated by Verity SBOM Validator &middot; verity.dev
</div>
</body>
</html>"""
