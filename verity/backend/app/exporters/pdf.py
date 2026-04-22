"""
PDF exporter for Verity scan results.
Uses WeasyPrint to render an HTML report to a PDF byte string.
"""

from typing import Any


_TEAL = "#1c9770"
_TEAL_LIGHT = "#edfaf3"
_TEAL_MID = "#bef3e2"
_DARK = "#1a1a2e"
_GRAY = "#464646"
_GRAY_LIGHT = "#6b7280"
_BORDER = "#e5e7eb"

_RISK_PALETTE: dict[str, tuple[str, str]] = {
    "LOW":      ("#22c55e", "#ffffff"),
    "MEDIUM":   ("#f59e0b", "#ffffff"),
    "HIGH":     ("#f97316", "#ffffff"),
    "CRITICAL": ("#dc2626", "#ffffff"),
    "UNKNOWN":  ("#9ca3af", "#ffffff"),
}

_GRADE_PALETTE: dict[str, str] = {
    "A": "#22c55e",
    "B": "#93cb52",
    "C": "#f59e0b",
    "D": "#f97316",
    "F": "#dc2626",
}

_SEV_PALETTE: dict[str, str] = {
    "ERROR":    "#dc2626",
    "WARNING":  "#f59e0b",
    "INFO":     "#3b82f6",
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


# ---------------------------------------------------------------------------
# Escape helper
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Badge helpers
# ---------------------------------------------------------------------------

def _badge(text: str, bg: str, fg: str = "#ffffff") -> str:
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 9px;'
        f'border-radius:20px;font-weight:700;font-size:0.8em;'
        f'letter-spacing:0.02em;white-space:nowrap;">{_esc(text)}</span>'
    )


def _risk_badge(level: str) -> str:
    bg, fg = _RISK_PALETTE.get(str(level).upper(), ("#9ca3af", "#ffffff"))
    return _badge(level.upper(), bg, fg)


def _grade_badge(grade: str) -> str:
    color = _GRADE_PALETTE.get(str(grade).upper(), "#9ca3af")
    return _badge(grade, color)


def _pass_badge(ok: bool, partial: bool = False) -> str:
    if ok:
        return _badge("PASS", "#22c55e")
    if partial:
        return _badge("PARTIAL", "#f59e0b")
    return _badge("FAIL", "#dc2626")


def _sev_badge(severity: str) -> str:
    color = _SEV_PALETTE.get(severity.upper(), "#9ca3af")
    return _badge(severity, color)


# ---------------------------------------------------------------------------
# Score bar helper
# ---------------------------------------------------------------------------

def _score_bar(score: float, max_score: float = 10.0, height: str = "6px") -> str:
    pct = min(100.0, max(0.0, score / max_score * 100))
    if pct >= 80:
        color = "#22c55e"
    elif pct >= 60:
        color = "#93cb52"
    elif pct >= 40:
        color = "#f59e0b"
    elif pct >= 20:
        color = "#f97316"
    else:
        color = "#dc2626"
    return (
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<div style="flex:1;background:#e5e7eb;border-radius:3px;height:{height};overflow:hidden;">'
        f'<div style="width:{pct:.1f}%;background:{color};height:{height};border-radius:3px;"></div>'
        f'</div>'
        f'<span style="font-size:0.78em;color:{_GRAY_LIGHT};min-width:28px;text-align:right;">'
        f'{score:.1f}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Section title helper
# ---------------------------------------------------------------------------

def _section(title: str) -> str:
    return (
        f'<div style="border-left:4px solid {_TEAL};padding-left:10px;'
        f'margin:28px 0 14px 0;">'
        f'<span style="font-size:1.0em;font-weight:700;color:{_GRAY};">{_esc(title)}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Cover page
# ---------------------------------------------------------------------------

def _build_cover(scan: dict) -> str:
    filename = _esc(scan.get("filename", "Unknown"))
    created_at = _esc(scan.get("created_at", ""))
    sbom_format = _esc((scan.get("sbom_format") or "").upper())
    fmt_version = _esc(scan.get("format_version") or "")
    risk_level = str(scan.get("risk_level", "UNKNOWN")).upper()
    risk_score = scan.get("risk_score", 0.0)

    quality = scan.get("quality") or {}
    q_score = quality.get("overall_score")
    q_grade = quality.get("grade") or ""

    ntia = scan.get("ntia_compliant", False)
    total = scan.get("total_components", 0)
    vulnerable = scan.get("vulnerable_components", 0)
    invalid = scan.get("invalid_components", 0)

    ntia_text = "Compliant" if ntia else "Non-compliant"
    ntia_color = "#22c55e" if ntia else "#dc2626"

    q_cell = (
        f'<div class="metric-cell">'
        f'<div class="metric-value" style="color:{_GRADE_PALETTE.get(q_grade, _GRAY)};">{_esc(q_grade)}</div>'
        f'<div class="metric-label">Quality Grade</div>'
        f'<div class="metric-sub">{q_score:.1f} / 10</div>'
        f'</div>'
    ) if q_score is not None else (
        f'<div class="metric-cell">'
        f'<div class="metric-value">—</div>'
        f'<div class="metric-label">Quality Grade</div>'
        f'</div>'
    )

    risk_bg, _ = _RISK_PALETTE.get(risk_level, ("#9ca3af", "#fff"))

    return f"""
    <div class="cover-page">
      <div class="cover-band">
        <div class="cover-brand">Verity</div>
        <div class="cover-report-title">SBOM Compliance Report</div>
      </div>

      <div class="cover-body">
        <div class="cover-filename">{filename}</div>
        <div class="cover-meta-row">
          <span>{sbom_format} {fmt_version}</span>
          <span class="dot">·</span>
          <span>{created_at}</span>
        </div>

        <div class="metrics-grid">
          <div class="metric-cell">
            <div class="metric-value">{total}</div>
            <div class="metric-label">Components</div>
          </div>
          <div class="metric-cell">
            <div class="metric-value" style="color:{'#dc2626' if vulnerable > 0 else _GRAY};">{vulnerable}</div>
            <div class="metric-label">Vulnerable</div>
            {f'<div class="metric-sub">{invalid} invalid fields</div>' if invalid else ''}
          </div>
          <div class="metric-cell">
            <div class="metric-value" style="color:{risk_bg};">{risk_level}</div>
            <div class="metric-label">Risk Level</div>
            <div class="metric-sub">Score {risk_score:.1f}</div>
          </div>
          {q_cell}
          <div class="metric-cell">
            <div class="metric-value" style="color:{ntia_color};">{ntia_text}</div>
            <div class="metric-label">NTIA Status</div>
          </div>
        </div>
      </div>
    </div>
    <div class="page-break"></div>
"""


# ---------------------------------------------------------------------------
# Quality section
# ---------------------------------------------------------------------------

def _build_quality_section(scan: dict) -> str:
    quality = scan.get("quality") or {}
    categories = quality.get("categories") or []
    if not categories:
        return ""

    overall = quality.get("overall_score", 0.0)
    grade = quality.get("grade") or ""
    grade_color = _GRADE_PALETTE.get(grade, _GRAY)

    cat_rows = ""
    for cat in categories:
        name = _esc(cat.get("name", ""))
        score = cat.get("score", 0.0)
        weight = cat.get("weight", 0)
        cat_rows += (
            f'<tr>'
            f'<td style="font-weight:500;color:{_GRAY};">{name}</td>'
            f'<td style="width:55%;padding-right:4px;">{_score_bar(score)}</td>'
            f'<td style="text-align:center;color:{_GRAY_LIGHT};">{weight}</td>'
            f'</tr>\n'
        )

    # Weakest categories for action items
    weak = sorted(
        [c for c in categories if c.get("score", 10) < 6.0],
        key=lambda c: c.get("score", 10),
    )[:4]
    action_items = "".join(
        f'<li style="margin-bottom:3px;"><strong>{_esc(c.get("name",""))}</strong>'
        f' — {c.get("score",0):.1f}/10</li>'
        for c in weak
    ) if weak else '<li>No categories below threshold.</li>'

    return f"""
    {_section(f"Quality Score: {overall:.1f}/10  {grade}")}
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;">
      <div style="font-size:3em;font-weight:900;color:{grade_color};line-height:1;">{_esc(grade)}</div>
      <div>
        <div style="font-size:1.4em;font-weight:700;color:{_GRAY};">{overall:.1f}<span style="font-size:0.6em;color:{_GRAY_LIGHT};"> / 10</span></div>
        <div style="font-size:0.8em;color:{_GRAY_LIGHT};">Overall Quality Score</div>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:30%;">Category</th>
          <th>Score</th>
          <th style="width:60px;text-align:center;">Weight</th>
        </tr>
      </thead>
      <tbody>
        {cat_rows}
      </tbody>
    </table>
    {f'''
    <div class="callout callout-warn">
      <div class="callout-title">Areas for Improvement</div>
      <ul style="margin:4px 0 0 0;padding-left:18px;font-size:0.88em;">{action_items}</ul>
    </div>''' if weak else ''}
"""


# ---------------------------------------------------------------------------
# Compliance section
# ---------------------------------------------------------------------------

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
            f'<tr style="background:{_TEAL_LIGHT};">'
            f'<td><strong>NTIA Minimum Elements</strong></td>'
            f'<td>{_pass_badge(ok)}</td>'
            f'<td>{_score_bar(score)}</td>'
            f'<td style="color:{_GRAY_LIGHT};">{passing}/{len(elements)} elements</td>'
            f'</tr>\n'
        )
        for elem in elements:
            elem_ok = elem.get("compliant", False)
            icon = "✓" if elem_ok else "✗"
            icon_color = "#22c55e" if elem_ok else "#dc2626"
            detail = _esc(elem.get("detail", ""))
            rows += (
                f'<tr>'
                f'<td style="padding-left:20px;color:{_GRAY_LIGHT};font-size:0.88em;">'
                f'<span style="color:{icon_color};font-weight:700;">{icon}</span> '
                f'{_esc(elem.get("element_name",""))}</td>'
                f'<td></td>'
                f'<td></td>'
                f'<td style="color:{_GRAY_LIGHT};font-size:0.85em;">{detail}</td>'
                f'</tr>\n'
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
            detail = f"SHALL: {req_p}/{req_t} &nbsp;·&nbsp; SHOULD: {add_p}/{add_t}"
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
            f'<tr style="background:{_TEAL_LIGHT};">'
            f'<td><strong>{_esc(label)}</strong></td>'
            f'<td>{_pass_badge(ok, partial)}</td>'
            f'<td>{_score_bar(score)}</td>'
            f'<td style="color:{_GRAY_LIGHT};">{detail}</td>'
            f'</tr>\n'
        )

    if not rows:
        return ""

    return f"""
    {_section("Compliance Standards")}
    <table>
      <thead>
        <tr>
          <th>Standard</th>
          <th style="width:80px;">Result</th>
          <th style="width:160px;">Score</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
"""


# ---------------------------------------------------------------------------
# Vulnerability section
# ---------------------------------------------------------------------------

def _build_vulnerability_section(scan: dict) -> str:
    components = scan.get("components") or []
    all_vulns: list[tuple[str, dict]] = []
    for comp in components:
        for vuln in (comp.get("vulnerabilities") or []):
            all_vulns.append((comp.get("name", ""), vuln))

    if not all_vulns:
        return ""

    all_vulns.sort(
        key=lambda x: (-(x[1].get("epss_score") or 0.0), -(x[1].get("cvss_score") or 0.0))
    )

    kev_count = sum(1 for _, v in all_vulns if v.get("in_kev"))
    high_epss = sum(1 for _, v in all_vulns if (v.get("epss_score") or 0) > 0.5)

    banner = ""
    if kev_count:
        banner = (
            f'<div class="callout callout-crit">'
            f'<strong>{kev_count} CVE(s) in CISA KEV catalog</strong> — active exploitation confirmed. Remediate immediately.'
            f'</div>'
        )

    rows = ""
    for comp_name, vuln in all_vulns[:50]:
        vid = _esc(vuln.get("id", ""))
        severity = str(vuln.get("severity", "UNKNOWN")).upper()
        cvss = vuln.get("cvss_score", 0.0)
        epss = vuln.get("epss_score")
        epss_pct = vuln.get("epss_percentile")
        in_kev = vuln.get("in_kev", False)
        fixed = _esc(vuln.get("fixed_version") or "")

        epss_cell = f"{epss:.3f}" if epss is not None else "—"
        if epss_pct is not None and epss is not None:
            epss_cell += f" ({epss_pct:.0f}th%)"

        kev_cell = _badge("KEV", "#dc2626") if in_kev else ""
        row_bg = "#fff1f2" if in_kev else ("#fffbeb" if (epss or 0) > 0.5 else "#ffffff")

        rows += (
            f'<tr style="background:{row_bg};">'
            f'<td style="font-family:monospace;font-size:0.85em;">{vid}</td>'
            f'<td style="font-size:0.88em;">{_esc(comp_name)}</td>'
            f'<td>{_risk_badge(severity)}</td>'
            f'<td style="text-align:center;font-size:0.88em;">{cvss:.1f}</td>'
            f'<td style="text-align:center;font-size:0.85em;">{epss_cell}</td>'
            f'<td style="text-align:center;">{kev_cell}</td>'
            f'<td style="font-size:0.82em;color:{_GRAY_LIGHT};">{fixed or "—"}</td>'
            f'</tr>\n'
        )

    note = (
        f'<p style="font-size:0.78em;color:{_GRAY_LIGHT};margin-top:4px;">'
        f'Showing top 50 of {len(all_vulns)}. Export JSON for full list.</p>'
        if len(all_vulns) > 50 else ""
    )

    return f"""
    {_section(f"Vulnerabilities — {len(all_vulns)} total · {kev_count} KEV · {high_epss} high-EPSS")}
    {banner}
    <table>
      <thead>
        <tr>
          <th>CVE / ID</th>
          <th>Component</th>
          <th>Severity</th>
          <th style="text-align:center;">CVSS</th>
          <th style="text-align:center;">EPSS</th>
          <th style="text-align:center;">KEV</th>
          <th>Fixed In</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    {note}
"""


# ---------------------------------------------------------------------------
# Component table
# ---------------------------------------------------------------------------

def _build_component_section(scan: dict) -> str:
    components = sorted(
        (scan.get("components") or []),
        key=lambda c: c.get("risk_score", 0.0),
        reverse=True,
    )
    if not components:
        return ""

    shown = components[:25]
    rows = ""
    for comp in shown:
        name = _esc(comp.get("name", ""))
        version = _esc(comp.get("version") or "—")
        supplier = _esc(comp.get("supplier") or "—")
        licenses = _esc(", ".join(comp.get("licenses") or []) or "—")
        risk = str(comp.get("risk_level", "")).upper()
        score = comp.get("risk_score", 0.0)
        vuln_count = len(comp.get("vulnerabilities") or [])
        purl = _esc((comp.get("purl") or "")[:40] + ("..." if len(comp.get("purl") or "") > 40 else ""))
        rows += (
            f'<tr>'
            f'<td style="font-weight:500;">{name}</td>'
            f'<td style="font-family:monospace;font-size:0.82em;">{version}</td>'
            f'<td style="font-size:0.85em;">{supplier}</td>'
            f'<td style="font-size:0.78em;color:{_GRAY_LIGHT};">{purl}</td>'
            f'<td style="font-size:0.85em;">{licenses}</td>'
            f'<td>{_risk_badge(risk)}</td>'
            f'<td style="text-align:center;font-size:0.85em;">{score:.0f}</td>'
            f'<td style="text-align:center;color:{"#dc2626" if vuln_count else _GRAY_LIGHT};">'
            f'{"<strong>" if vuln_count else ""}{vuln_count if vuln_count else "—"}{"</strong>" if vuln_count else ""}</td>'
            f'</tr>\n'
        )

    total = len(components)
    note = (
        f'<p style="font-size:0.78em;color:{_GRAY_LIGHT};margin-top:4px;">'
        f'Showing top {len(shown)} of {total} by risk score. Export JSON for full list.</p>'
        if total > len(shown) else ""
    )

    return f"""
    {_section(f"Component Inventory — {total} components")}
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Version</th>
          <th>Supplier</th>
          <th>PURL</th>
          <th>License</th>
          <th>Risk</th>
          <th style="text-align:center;">Score</th>
          <th style="text-align:center;">Vulns</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    {note}
"""


# ---------------------------------------------------------------------------
# Validation issues section
# ---------------------------------------------------------------------------

def _build_issues_section(scan: dict) -> str:
    issues = scan.get("validation_issues") or []
    if not issues:
        return ""

    errors = [i for i in issues if i.get("severity") == "ERROR"]
    warnings = [i for i in issues if i.get("severity") == "WARNING"]
    infos = [i for i in issues if i.get("severity") == "INFO"]

    rows = ""
    for group in [errors, warnings, infos]:
        for issue in group:
            sev = issue.get("severity", "")
            code = _esc(issue.get("code", ""))
            msg = _esc(issue.get("message", ""))
            comp = _esc(issue.get("component_name") or "—")
            row_bg = "#fff1f2" if sev == "ERROR" else ("#fffbeb" if sev == "WARNING" else "#ffffff")
            rows += (
                f'<tr style="background:{row_bg};">'
                f'<td>{_sev_badge(sev)}</td>'
                f'<td style="font-family:monospace;font-size:0.82em;">{code}</td>'
                f'<td style="font-size:0.88em;">{msg}</td>'
                f'<td style="font-size:0.88em;color:{_GRAY_LIGHT};">{comp}</td>'
                f'</tr>\n'
            )

    summary = f"{len(errors)} errors · {len(warnings)} warnings · {len(infos)} info"

    return f"""
    {_section(f"Validation Issues — {summary}")}
    <table>
      <thead>
        <tr>
          <th style="width:80px;">Severity</th>
          <th style="width:160px;">Code</th>
          <th>Message</th>
          <th style="width:130px;">Component</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
"""


# ---------------------------------------------------------------------------
# Main HTML builder
# ---------------------------------------------------------------------------

def _build_html(scan: dict) -> str:
    filename = _esc(scan.get("filename", "Unknown"))

    cover = _build_cover(scan)
    quality_section = _build_quality_section(scan)
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
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    color: {_GRAY};
    margin: 0;
    padding: 0;
    font-size: 11.5px;
    line-height: 1.55;
  }}

  /* Cover */
  .cover-page {{
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }}
  .cover-band {{
    background: {_TEAL};
    color: #ffffff;
    padding: 40px 48px 36px;
  }}
  .cover-brand {{
    font-size: 2em;
    font-weight: 900;
    letter-spacing: 0.06em;
    margin-bottom: 6px;
    opacity: 0.9;
  }}
  .cover-report-title {{
    font-size: 1.35em;
    font-weight: 600;
    opacity: 0.85;
  }}
  .cover-body {{
    padding: 36px 48px;
    flex: 1;
  }}
  .cover-filename {{
    font-size: 1.5em;
    font-weight: 700;
    color: {_GRAY};
    word-break: break-all;
    margin-bottom: 6px;
  }}
  .cover-meta-row {{
    color: {_GRAY_LIGHT};
    font-size: 0.9em;
    margin-bottom: 32px;
  }}
  .dot {{ margin: 0 8px; }}
  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1px;
    background: {_BORDER};
    border: 1px solid {_BORDER};
    border-radius: 10px;
    overflow: hidden;
    max-width: 560px;
  }}
  .metric-cell {{
    background: #ffffff;
    padding: 18px 20px;
  }}
  .metric-value {{
    font-size: 1.6em;
    font-weight: 800;
    color: {_GRAY};
    line-height: 1.1;
  }}
  .metric-label {{
    font-size: 0.78em;
    color: {_GRAY_LIGHT};
    margin-top: 3px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .metric-sub {{
    font-size: 0.78em;
    color: #9ca3af;
    margin-top: 2px;
  }}

  /* Content area */
  .content {{ padding: 24px 48px 40px; }}

  /* Tables */
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 10px;
    font-size: 0.87em;
  }}
  th {{
    background: {_TEAL_MID};
    color: {_GRAY};
    padding: 7px 10px;
    text-align: left;
    font-weight: 700;
    font-size: 0.82em;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  td {{
    padding: 6px 10px;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: middle;
  }}
  tr:nth-child(even) td {{ background: #fafafa; }}

  /* Callout boxes */
  .callout {{
    padding: 10px 14px;
    border-radius: 6px;
    margin-bottom: 12px;
    font-size: 0.88em;
  }}
  .callout-title {{
    font-weight: 700;
    margin-bottom: 4px;
  }}
  .callout-crit {{
    background: #fff1f2;
    border-left: 4px solid #dc2626;
    color: #991b1b;
  }}
  .callout-warn {{
    background: #fffbeb;
    border-left: 4px solid #f59e0b;
    color: #92400e;
  }}

  /* Page layout */
  .page-break {{ page-break-after: always; }}
  .footer {{
    text-align: center;
    color: #d1d5db;
    font-size: 0.76em;
    padding: 20px 48px;
    border-top: 1px solid {_BORDER};
    margin-top: 32px;
  }}
  @page {{ margin: 1.4cm 1.2cm; }}
</style>
</head>
<body>
{cover}
<div class="content">
{quality_section}
{compliance_section}
{vuln_section}
{component_section}
{issues_section}
</div>
<div class="footer">
  Generated by Verity SBOM Validator
</div>
</body>
</html>"""
