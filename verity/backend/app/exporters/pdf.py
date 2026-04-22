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

_RISK_PALETTE: dict[str, str] = {
    "LOW":      "#93cb52",
    "MEDIUM":   "#6b7280",
    "HIGH":     "#464646",
    "CRITICAL": "#dc2626",
    "UNKNOWN":  "#9ca3af",
}

_GRADE_PALETTE: dict[str, str] = {
    "A": "#93cb52",
    "B": "#93cb52",
    "C": "#6b7280",
    "D": "#6b7280",
    "F": "#dc2626",
}

_SEV_PALETTE: dict[str, str] = {
    "ERROR":    "#dc2626",
    "WARNING":  "#464646",
    "INFO":     "#6b7280",
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
# Colored text helpers (no pill/badge backgrounds)
# ---------------------------------------------------------------------------

def _risk_label(level: str) -> str:
    color = _RISK_PALETTE.get(str(level).upper(), "#9ca3af")
    return f'<span style="color:{color};font-weight:700;font-size:0.85em;">{_esc(level.upper())}</span>'


def _pass_label(ok: bool, partial: bool = False) -> str:
    if ok:
        return f'<span style="color:#93cb52;font-weight:700;">Pass</span>'
    if partial:
        return f'<span style="color:#6b7280;font-weight:700;">Partial</span>'
    return f'<span style="color:#dc2626;font-weight:700;">Fail</span>'


def _sev_label(severity: str) -> str:
    color = _SEV_PALETTE.get(severity.upper(), "#9ca3af")
    return f'<span style="color:{color};font-weight:700;font-size:0.85em;">{_esc(severity)}</span>'


def _kev_label() -> str:
    return f'<span style="color:#dc2626;font-weight:700;font-size:0.82em;">KEV</span>'


# ---------------------------------------------------------------------------
# Score bar helper
# ---------------------------------------------------------------------------

def _score_bar(score: float, max_score: float = 10.0, height: str = "5px") -> str:
    pct = min(100.0, max(0.0, score / max_score * 100))
    if pct >= 70:
        color = "#93cb52"
    elif pct >= 40:
        color = "#6b7280"
    else:
        color = "#dc2626"
    return (
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<div style="flex:1;background:#e5e7eb;border-radius:3px;height:{height};overflow:hidden;">'
        f'<div style="width:{pct:.1f}%;background:{color};height:{height};border-radius:3px;"></div>'
        f'</div>'
        f'<span style="font-size:0.86em;color:{_GRAY_LIGHT};min-width:30px;text-align:right;">'
        f'{score:.1f}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Section title helper
# ---------------------------------------------------------------------------

def _section(title: str) -> str:
    return (
        f'<div style="border-left:3px solid {_TEAL};padding-left:10px;'
        f'margin:26px 0 12px 0;">'
        f'<span style="font-family:\'DM Sans\',sans-serif;font-size:1.15em;font-weight:700;color:{_GRAY};letter-spacing:0.01em;">{_esc(title)}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Report header (compact — no forced page break)
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
    ntia_color = "#93cb52" if ntia else "#dc2626"
    risk_color = _RISK_PALETTE.get(risk_level, "#9ca3af")
    vuln_color = "#dc2626" if vulnerable > 0 else _GRAY

    q_value = f'{_esc(q_grade)} &nbsp;<span style="font-size:0.6em;font-weight:400;color:{_GRAY_LIGHT};">{q_score:.1f}/10</span>' if q_score is not None else "N/A"
    q_color = _GRADE_PALETTE.get(q_grade, _GRAY) if q_score is not None else _GRAY_LIGHT

    invalid_note = f'<div class="metric-sub">{invalid} invalid</div>' if invalid else ''

    return f"""
    <div class="report-header">
      <div class="header-band">
        <div class="header-brand">Verity</div>
        <div class="header-tagline">SBOM Compliance Report</div>
      </div>
      <div class="header-body">
        <div class="doc-filename">{filename}</div>
        <div class="doc-meta">{sbom_format}{(' ' + fmt_version) if fmt_version else ''}  &nbsp;·&nbsp;  {created_at}</div>
        <div class="metrics-strip">
          <div class="metric-item">
            <div class="metric-num">{total}</div>
            <div class="metric-lbl">Components</div>
          </div>
          <div class="metric-divider"></div>
          <div class="metric-item">
            <div class="metric-num" style="color:{vuln_color};">{vulnerable}</div>
            <div class="metric-lbl">Vulnerable</div>
            {invalid_note}
          </div>
          <div class="metric-divider"></div>
          <div class="metric-item">
            <div class="metric-num" style="color:{risk_color};">{risk_level}</div>
            <div class="metric-lbl">Risk Level</div>
            <div class="metric-sub">score {risk_score:.1f}</div>
          </div>
          <div class="metric-divider"></div>
          <div class="metric-item">
            <div class="metric-num" style="color:{q_color};">{q_value}</div>
            <div class="metric-lbl">Quality</div>
          </div>
          <div class="metric-divider"></div>
          <div class="metric-item">
            <div class="metric-num" style="color:{ntia_color};">{ntia_text}</div>
            <div class="metric-lbl">NTIA</div>
          </div>
        </div>
      </div>
    </div>
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
        for feat in (cat.get("features") or []):
            if not feat.get("applicable", True):
                continue
            fkey = _esc(feat.get("key", ""))
            fscore = float(feat.get("score", 0.0))
            fdetail = _esc(feat.get("detail", ""))
            icon = "✓" if fscore >= 10 else ("~" if fscore > 0 else "✗")
            icon_color = "#93cb52" if fscore >= 10 else ("#6b7280" if fscore > 0 else "#dc2626")
            cat_rows += (
                f'<tr>'
                f'<td style="padding-left:18px;font-size:0.8em;color:{_GRAY_LIGHT};">'
                f'<span style="color:{icon_color};font-weight:700;">{icon}</span> '
                f'<span style="font-family:monospace;">{fkey}</span>'
                f'</td>'
                f'<td style="font-size:0.8em;color:{_GRAY_LIGHT};" colspan="2">{fdetail}</td>'
                f'</tr>\n'
            )

    # Weakest categories for action items
    weak = sorted(
        [c for c in categories if c.get("score", 10) < 6.0],
        key=lambda c: c.get("score", 10),
    )[:4]
    action_items = "".join(
        f'<li style="margin-bottom:3px;"><strong>{_esc(c.get("name",""))}</strong>'
        f': {c.get("score",0):.1f}/10</li>'
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
            f'<td>{_pass_label(ok)}</td>'
            f'<td>{_score_bar(score)}</td>'
            f'<td style="color:{_GRAY_LIGHT};">{passing}/{len(elements)} elements</td>'
            f'</tr>\n'
        )
        for elem in elements:
            elem_ok = elem.get("compliant", False)
            icon = "+" if elem_ok else "-"
            icon_color = "#93cb52" if elem_ok else "#dc2626"
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
            f'<td>{_pass_label(ok, partial)}</td>'
            f'<td>{_score_bar(score)}</td>'
            f'<td style="color:{_GRAY_LIGHT};">{detail}</td>'
            f'</tr>\n'
        )

        # Per-check records for this standard (group unique checks; skip N/A)
        records = [r for r in (std.get("records") or []) if r.get("applicable", True)]
        if records:
            # De-duplicate: for per-component checks show only the first failing instance
            seen: set[str] = set()
            for r in records:
                ck = r.get("check_key", "")
                rec_score = float(r.get("score", 0.0))
                subject = _esc(r.get("subject_id", ""))
                rec_detail = _esc(r.get("detail", ""))
                tier = r.get("tier", "required")
                tier_label = "SHALL" if tier == "required" else "SHOULD" if tier == "additional" else "MAY"
                icon = "✓" if rec_score >= 10 else ("~" if rec_score >= 5 else "✗")
                icon_color = "#93cb52" if rec_score >= 10 else ("#6b7280" if rec_score >= 5 else "#dc2626")
                dedup_key = ck if rec_score >= 10 else f"{ck}::{subject}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                rows += (
                    f'<tr>'
                    f'<td style="padding-left:20px;font-size:0.82em;color:{_GRAY_LIGHT};">'
                    f'<span style="color:{icon_color};font-weight:700;">{icon}</span> '
                    f'<span style="font-family:monospace;">{_esc(ck)}</span>'
                    f'{f" <em>({subject})</em>" if subject and subject != "document" else ""}'
                    f'</td>'
                    f'<td style="font-size:0.78em;color:{_GRAY_LIGHT};">{tier_label}</td>'
                    f'<td></td>'
                    f'<td style="font-size:0.82em;color:{_GRAY_LIGHT};">{rec_detail}</td>'
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
            f'<p style="font-size:0.88em;color:#dc2626;font-weight:700;margin-bottom:8px;">'
            f'{kev_count} CVE(s) in CISA KEV catalog. Active exploitation confirmed. Remediate immediately.'
            f'</p>'
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

        epss_cell = f"{epss:.3f}" if epss is not None else "N/A"
        if epss_pct is not None and epss is not None:
            epss_cell += f" {epss_pct:.0f}th pct"

        kev_cell = _kev_label() if in_kev else ""
        row_bg = "#fff9f9" if in_kev else "#ffffff"

        rows += (
            f'<tr style="background:{row_bg};">'
            f'<td style="font-family:monospace;font-size:0.85em;">{vid}</td>'
            f'<td style="font-size:0.88em;">{_esc(comp_name)}</td>'
            f'<td>{_risk_label(severity)}</td>'
            f'<td style="text-align:center;font-size:0.88em;">{cvss:.1f}</td>'
            f'<td style="text-align:center;font-size:0.85em;">{epss_cell}</td>'
            f'<td style="text-align:center;">{kev_cell}</td>'
            f'<td style="font-size:0.82em;color:{_GRAY_LIGHT};">{fixed or "N/A"}</td>'
            f'</tr>\n'
        )

    note = (
        f'<p style="font-size:0.78em;color:{_GRAY_LIGHT};margin-top:4px;">'
        f'Showing top 50 of {len(all_vulns)}. Export JSON for full list.</p>'
        if len(all_vulns) > 50 else ""
    )

    return f"""
    {_section(f"Vulnerabilities: {len(all_vulns)} total  {kev_count} KEV  {high_epss} high-EPSS")}
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
        version = _esc(comp.get("version") or "N/A")
        supplier = _esc(comp.get("supplier") or "N/A")
        licenses = _esc(", ".join(comp.get("licenses") or []) or "N/A")
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
            f'<td>{_risk_label(risk)}</td>'
            f'<td style="text-align:center;font-size:0.85em;">{score:.0f}</td>'
            f'<td style="text-align:center;color:{"#dc2626" if vuln_count else _GRAY_LIGHT};">'
            f'{"<strong>" if vuln_count else ""}{vuln_count if vuln_count else "0"}{"</strong>" if vuln_count else ""}</td>'
            f'</tr>\n'
        )

    total = len(components)
    note = (
        f'<p style="font-size:0.78em;color:{_GRAY_LIGHT};margin-top:4px;">'
        f'Showing top {len(shown)} of {total} by risk score. Export JSON for full list.</p>'
        if total > len(shown) else ""
    )

    return f"""
    {_section(f"Component Inventory: {total} components")}
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
# Dependency graph section
# ---------------------------------------------------------------------------

def _build_dep_graph_section(scan: dict) -> str:
    dg = scan.get("dependency_graph") or {}
    nodes = dg.get("nodes") or []
    if not nodes:
        return ""

    edges = dg.get("edges") or []
    orphans = dg.get("orphans") or []
    is_complete = dg.get("is_complete", False)
    max_depth = dg.get("max_depth", 0)
    primary_ref = _esc(dg.get("primary_component_ref") or "")
    orphan_count = len(orphans)

    complete_label = _pass_label(is_complete)
    orphan_note = ""
    if orphan_count:
        orphan_refs = ", ".join(_esc(o) for o in orphans[:10])
        if orphan_count > 10:
            orphan_refs += f" … +{orphan_count - 10} more"
        orphan_note = (
            f'<p style="margin-top:6px;font-size:0.85em;color:#f59e0b;">'
            f'<strong>Orphaned components:</strong> {orphan_refs}</p>'
        )

    rows = (
        f'<tr><td>Total nodes</td><td>{len(nodes)}</td></tr>\n'
        f'<tr><td>Dependency edges</td><td>{len(edges)}</td></tr>\n'
        f'<tr><td>Max depth</td><td>{max_depth}</td></tr>\n'
        f'<tr><td>Orphaned components</td><td style="color:{"#f59e0b" if orphan_count else _GRAY_LIGHT};">'
        f'{orphan_count}</td></tr>\n'
        f'<tr><td>Graph complete</td><td>{complete_label}</td></tr>\n'
    )
    if primary_ref:
        rows += f'<tr><td>Primary component</td><td style="font-family:monospace;font-size:0.9em;">{primary_ref}</td></tr>\n'

    return f"""
    {_section("Dependency Graph")}
    <table style="max-width:480px;">
      <tbody>{rows}</tbody>
    </table>
    {orphan_note}
"""


# ---------------------------------------------------------------------------
# Policy result section
# ---------------------------------------------------------------------------

def _build_policy_section(scan: dict) -> str:
    policy = scan.get("policy_result") or {}
    if not policy:
        return ""

    overall = str(policy.get("overall", "")).upper()
    outcomes = policy.get("outcomes") or []
    if not outcomes:
        return ""

    ok = overall == "PASS"
    warn = overall == "WARN"
    overall_color = "#93cb52" if ok else ("#f59e0b" if warn else "#dc2626")
    triggered = [o for o in outcomes if o.get("triggered")]

    rows = ""
    for o in outcomes:
        rule_id = _esc(o.get("rule_id", ""))
        desc = _esc(o.get("description", ""))
        action = _esc(o.get("action", ""))
        detail = _esc(o.get("detail", ""))
        is_triggered = o.get("triggered", False)
        icon = "✗" if is_triggered else "✓"
        action_color = "#dc2626" if action == "block" else "#f59e0b"
        icon_color = action_color if is_triggered else "#93cb52"
        rows += (
            f'<tr>'
            f'<td style="font-family:monospace;font-size:0.85em;">{rule_id}</td>'
            f'<td><span style="color:{icon_color};font-weight:700;">{icon}</span></td>'
            f'<td style="font-size:0.88em;">{desc}</td>'
            f'<td style="font-size:0.82em;color:{action_color};font-weight:600;">{action.upper()}</td>'
            f'<td style="font-size:0.82em;color:{_GRAY_LIGHT};">{detail}</td>'
            f'</tr>\n'
        )

    summary = f'{len(triggered)} rule{"s" if len(triggered) != 1 else ""} triggered' if triggered else 'No rules triggered'

    return f"""
    {_section(f"Policy Evaluation: {overall}")}
    <div style="display:inline-block;margin-bottom:10px;padding:5px 14px;border-radius:6px;background:{_TEAL_LIGHT};">
      <span style="font-weight:700;color:{overall_color};font-size:1.05em;">{_esc(overall)}</span>
      <span style="color:{_GRAY_LIGHT};font-size:0.88em;margin-left:10px;">{_esc(summary)}</span>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:130px;">Rule ID</th>
          <th style="width:50px;">Status</th>
          <th>Description</th>
          <th style="width:70px;">Action</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
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
            comp = _esc(issue.get("component_name") or "N/A")
            rows += (
                f'<tr>'
                f'<td>{_sev_label(sev)}</td>'
                f'<td style="font-family:monospace;font-size:0.82em;">{code}</td>'
                f'<td style="font-size:0.88em;">{msg}</td>'
                f'<td style="font-size:0.88em;color:{_GRAY_LIGHT};">{comp}</td>'
                f'</tr>\n'
            )

    summary = f"{len(errors)} errors  {len(warnings)} warnings  {len(infos)} info"

    return f"""
    {_section(f"Validation Issues: {summary}")}
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
    dep_graph_section = _build_dep_graph_section(scan)
    policy_section = _build_policy_section(scan)
    issues_section = _build_issues_section(scan)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Verity SBOM Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin=""/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: 'Inter', sans-serif;
    color: {_GRAY};
    margin: 0;
    padding: 0;
    font-size: 11.5px;
    line-height: 1.65;
  }}

  /* ---- Report header (compact, first page only) ---- */
  .report-header {{
    margin-bottom: 0;
  }}
  .header-band {{
    background: {_TEAL};
    color: #ffffff;
    padding: 18px 40px;
    display: flex;
    align-items: baseline;
    gap: 20px;
  }}
  .header-brand {{
    font-family: 'DM Sans', sans-serif;
    font-size: 1.6em;
    font-weight: 700;
    letter-spacing: 0.04em;
  }}
  .header-tagline {{
    font-family: 'Inter', sans-serif;
    font-size: 0.9em;
    font-weight: 400;
    opacity: 0.8;
  }}
  .header-body {{
    padding: 20px 40px 0;
    border-bottom: 1px solid {_BORDER};
    padding-bottom: 20px;
  }}
  .doc-filename {{
    font-family: 'DM Sans', sans-serif;
    font-size: 1.3em;
    font-weight: 700;
    color: {_GRAY};
    word-break: break-all;
    margin-bottom: 5px;
  }}
  .doc-meta {{
    font-family: 'Inter', sans-serif;
    color: {_GRAY_LIGHT};
    font-size: 0.92em;
    margin-bottom: 16px;
  }}

  /* ---- Metrics strip ---- */
  .metrics-strip {{
    display: flex;
    align-items: stretch;
    border: 1px solid {_BORDER};
    border-radius: 8px;
    overflow: hidden;
  }}
  .metric-item {{
    flex: 1;
    padding: 12px 16px;
    background: #ffffff;
  }}
  .metric-divider {{
    width: 1px;
    background: {_BORDER};
    flex-shrink: 0;
  }}
  .metric-num {{
    font-family: 'DM Sans', sans-serif;
    font-size: 1.35em;
    font-weight: 700;
    color: {_GRAY};
    line-height: 1.15;
  }}
  .metric-lbl {{
    font-family: 'Inter', sans-serif;
    font-size: 0.78em;
    color: {_GRAY_LIGHT};
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-top: 3px;
  }}
  .metric-sub {{
    font-family: 'Inter', sans-serif;
    font-size: 0.78em;
    color: #9ca3af;
    margin-top: 2px;
  }}

  /* ---- Main content ---- */
  .content {{
    padding: 8px 40px 40px;
  }}

  /* ---- Tables ---- */
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 12px;
    font-size: 0.93em;
  }}
  th {{
    font-family: 'DM Sans', sans-serif;
    background: {_TEAL_MID};
    color: {_GRAY};
    padding: 8px 12px;
    text-align: left;
    font-weight: 700;
    font-size: 0.84em;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border-bottom: 1px solid {_BORDER};
  }}
  td {{
    padding: 7px 12px;
    border-bottom: 1px solid #f0f0f0;
    vertical-align: middle;
  }}
  tr:last-child td {{ border-bottom: none; }}

  /* ---- Page setup ---- */
  @page {{
    margin: 1.2cm 1.0cm;
    @bottom-left {{
      content: "Generated by Verity SBOM Validator";
      font-family: 'Inter', sans-serif;
      font-size: 8px;
      color: #d1d5db;
    }}
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-family: 'Inter', sans-serif;
      font-size: 8px;
      color: #d1d5db;
    }}
  }}
</style>
</head>
<body>
{cover}
<div class="content">
{quality_section}
{compliance_section}
{vuln_section}
{component_section}
{dep_graph_section}
{policy_section}
{issues_section}
</div>
</body>
</html>"""
