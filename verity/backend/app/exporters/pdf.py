"""
PDF exporter for Verity scan results.
Uses WeasyPrint to render an HTML report to a PDF byte string.
"""

from typing import Any


# Brand colors
_GREEN = "#93cb52"
_TEAL = "#1c9770"
_LIGHT_TEAL = "#bef3e2"
_LIGHT_RED = "#f2eeee"
_DARK_GRAY = "#464646"

# Risk level badge colors
_RISK_COLORS = {
    "LOW": (_GREEN, "#ffffff"),
    "MEDIUM": ("#f5a623", "#ffffff"),
    "HIGH": ("#e8682a", "#ffffff"),
    "CRITICAL": ("#c0392b", "#ffffff"),
}


def export_pdf(scan_detail: dict) -> bytes:
    """
    Render a scan result as a PDF report using WeasyPrint.

    Args:
        scan_detail: Full scan result dictionary (from ScanDetailOut.model_dump()).

    Returns:
        PDF content as bytes.

    Raises:
        ImportError: If WeasyPrint is not installed.
        RuntimeError: If PDF rendering fails.
    """
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
    """HTML-escape a value for safe insertion into HTML."""
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
    """Return an inline-styled HTML span for a risk level badge."""
    bg, fg = _RISK_COLORS.get(str(level).upper(), ("#888888", "#ffffff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:3px 10px;'
        f'border-radius:4px;font-weight:bold;font-size:0.9em;">'
        f"{_esc(level)}</span>"
    )


def _build_html(scan: dict) -> str:
    """Build the full HTML report string from a scan detail dict."""
    filename = _esc(scan.get("filename", "Unknown"))
    created_at = _esc(scan.get("created_at", ""))
    risk_level = str(scan.get("risk_level", "UNKNOWN")).upper()
    risk_score = scan.get("risk_score", 0.0)
    total = scan.get("total_components", 0)
    vulnerable = scan.get("vulnerable_components", 0)
    invalid = scan.get("invalid_components", 0)
    ntia = "Yes" if scan.get("ntia_compliant") else "No"
    sbom_format = _esc(scan.get("sbom_format", ""))
    format_version = _esc(scan.get("format_version") or "")
    vuln_enabled = "Yes" if scan.get("vuln_check_enabled") else "No"

    # Validation issues table rows
    issues_rows = ""
    for issue in scan.get("validation_issues") or []:
        sev = _esc(issue.get("severity", ""))
        code = _esc(issue.get("code", ""))
        msg = _esc(issue.get("message", ""))
        comp = _esc(issue.get("component_name") or "")
        row_bg = _LIGHT_RED if sev == "ERROR" else "#ffffff"
        issues_rows += (
            f'<tr style="background:{row_bg};">'
            f"<td>{sev}</td><td>{code}</td><td>{msg}</td><td>{comp}</td>"
            f"</tr>\n"
        )

    if not issues_rows:
        issues_rows = '<tr><td colspan="4" style="color:#888;">No validation issues found.</td></tr>'

    # Component table rows
    comp_rows = ""
    for comp in scan.get("components") or []:
        name = _esc(comp.get("name", ""))
        version = _esc(comp.get("version") or "")
        comp_risk = str(comp.get("risk_level", "")).upper()
        comp_score = comp.get("risk_score", 0.0)
        vuln_count = len(comp.get("vulnerabilities") or [])
        supplier = _esc(comp.get("supplier") or "")
        missing = ", ".join(comp.get("missing_fields") or [])
        comp_rows += (
            f"<tr>"
            f"<td>{name}</td>"
            f"<td>{version}</td>"
            f"<td>{supplier}</td>"
            f"<td>{_risk_badge(comp_risk)}</td>"
            f'<td style="text-align:center;">{comp_score:.1f}</td>'
            f'<td style="text-align:center;">{vuln_count}</td>'
            f"<td><small>{_esc(missing)}</small></td>"
            f"</tr>\n"
        )

    if not comp_rows:
        comp_rows = '<tr><td colspan="7" style="color:#888;">No components found.</td></tr>'

    # Summary risk distribution
    summary = scan.get("summary") or {}
    risk_dist = summary.get("risk_distribution") or {}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Verity SBOM Report - {filename}</title>
<style>
  *, *::before, *::after {{
    box-sizing: border-box;
  }}
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    color: {_DARK_GRAY};
    margin: 0;
    padding: 0;
    font-size: 13px;
    line-height: 1.5;
  }}
  .header {{
    background: {_TEAL};
    color: #ffffff;
    padding: 24px 32px;
  }}
  .header h1 {{
    margin: 0 0 4px 0;
    font-size: 1.8em;
    letter-spacing: 0.03em;
  }}
  .header .subtitle {{
    font-size: 0.95em;
    opacity: 0.85;
  }}
  .content {{
    padding: 24px 32px;
  }}
  .section-title {{
    color: {_TEAL};
    font-size: 1.1em;
    font-weight: bold;
    margin: 24px 0 10px 0;
    border-bottom: 2px solid {_LIGHT_TEAL};
    padding-bottom: 4px;
  }}
  .summary-grid {{
    display: table;
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 16px;
  }}
  .summary-grid td, .summary-grid th {{
    padding: 8px 12px;
    border: 1px solid #ddd;
    text-align: left;
  }}
  .summary-grid th {{
    background: {_LIGHT_TEAL};
    font-weight: bold;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 16px;
  }}
  th {{
    background: {_LIGHT_TEAL};
    color: {_DARK_GRAY};
    padding: 8px 10px;
    text-align: left;
    font-size: 0.9em;
  }}
  td {{
    padding: 7px 10px;
    border-bottom: 1px solid #eeeeee;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{
    background: #f9f9f9;
  }}
  .risk-dist {{
    display: table;
    width: auto;
    border-collapse: separate;
    border-spacing: 8px;
    margin: 8px 0 16px 0;
  }}
  .risk-dist td {{
    padding: 6px 14px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 0.9em;
    border: none;
  }}
  .footer {{
    text-align: center;
    color: #aaa;
    font-size: 0.8em;
    margin-top: 40px;
    padding: 16px 0;
    border-top: 1px solid #eee;
  }}
  @page {{
    margin: 1.5cm;
  }}
</style>
</head>
<body>
<div class="header">
  <h1>Verity SBOM Report</h1>
  <div class="subtitle">
    {filename} &nbsp;|&nbsp; {created_at} &nbsp;|&nbsp; Format: {sbom_format} {format_version}
  </div>
</div>
<div class="content">

  <div class="section-title">Overall Risk</div>
  <p>
    Risk Level: {_risk_badge(risk_level)}
    &nbsp;&nbsp;
    Risk Score: <strong>{risk_score:.1f}</strong>
  </p>

  <div class="section-title">Summary Statistics</div>
  <table class="summary-grid">
    <tr>
      <th>Metric</th>
      <th>Value</th>
    </tr>
    <tr><td>Total Components</td><td>{total}</td></tr>
    <tr><td>Vulnerable Components</td><td>{vulnerable}</td></tr>
    <tr><td>Invalid Components</td><td>{invalid}</td></tr>
    <tr><td>NTIA Compliant</td><td>{ntia}</td></tr>
    <tr><td>Vulnerability Check Performed</td><td>{vuln_enabled}</td></tr>
    <tr><td>Overall Risk Score</td><td>{risk_score:.2f}</td></tr>
  </table>

  <div class="section-title">Risk Distribution</div>
  <table>
    <tr>
      <th>LOW</th>
      <th>MEDIUM</th>
      <th>HIGH</th>
      <th>CRITICAL</th>
    </tr>
    <tr>
      <td style="background:{_RISK_COLORS['LOW'][0]};color:#fff;text-align:center;font-weight:bold;">
        {risk_dist.get("LOW", 0)}
      </td>
      <td style="background:{_RISK_COLORS['MEDIUM'][0]};color:#fff;text-align:center;font-weight:bold;">
        {risk_dist.get("MEDIUM", 0)}
      </td>
      <td style="background:{_RISK_COLORS['HIGH'][0]};color:#fff;text-align:center;font-weight:bold;">
        {risk_dist.get("HIGH", 0)}
      </td>
      <td style="background:{_RISK_COLORS['CRITICAL'][0]};color:#fff;text-align:center;font-weight:bold;">
        {risk_dist.get("CRITICAL", 0)}
      </td>
    </tr>
  </table>

  <div class="section-title">Validation Issues</div>
  <table>
    <tr>
      <th>Severity</th>
      <th>Code</th>
      <th>Message</th>
      <th>Component</th>
    </tr>
    {issues_rows}
  </table>

  <div class="section-title">Components</div>
  <table>
    <tr>
      <th>Name</th>
      <th>Version</th>
      <th>Supplier</th>
      <th>Risk Level</th>
      <th>Score</th>
      <th>Vulns</th>
      <th>Missing Fields</th>
    </tr>
    {comp_rows}
  </table>

</div>
<div class="footer">
  Generated by Verity SBOM Validator &middot; verity.dev
</div>
</body>
</html>"""

    return html
