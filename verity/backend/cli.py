"""
Verity CLI - SBOM validation and risk assessment from the command line.

Usage:
    verity scan <file> [OPTIONS]
    verity version
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

_VERSION = "0.1.0"

_LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """Verity - SBOM Validator and Risk Assessment Tool."""
    pass


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------

@cli.command()
def version():
    """Print the Verity version and exit."""
    click.echo(f"Verity {_VERSION}")


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file", type=click.Path(exists=True, readable=True, dir_okay=False))
@click.option(
    "--vuln-check/--no-vuln-check",
    default=True,
    show_default=True,
    help="Check components against OSV.dev for known vulnerabilities.",
)
@click.option(
    "--fail-on",
    default="HIGH",
    show_default=True,
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    help="Exit with code 1 if the overall risk level meets or exceeds this level.",
)
@click.option(
    "--output",
    "output_format",
    default="text",
    show_default=True,
    type=click.Choice(["text", "json"], case_sensitive=False),
    help="Output format.",
)
@click.option(
    "--no-save",
    is_flag=True,
    default=False,
    help="Do not persist the scan result to history.",
)
def scan(
    file: str,
    vuln_check: bool,
    fail_on: str,
    output_format: str,
    no_save: bool,
) -> None:
    """
    Parse, validate, and risk-assess an SBOM file.

    FILE can be a CycloneDX JSON/XML or SPDX JSON/tag-value document.
    """
    file_path = Path(file)

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        click.secho(f"Error reading file: {exc}", fg="red", err=True)
        sys.exit(2)

    result = asyncio.run(
        _run_scan(
            content=content,
            filename=file_path.name,
            vuln_check=vuln_check,
        )
    )

    if output_format == "json":
        _output_json(result)
    else:
        _output_text(result)

    # Determine exit code based on fail-on threshold
    overall_level = result.get("risk_level", "LOW").upper()
    fail_threshold = _LEVEL_ORDER.get(fail_on.upper(), 2)
    actual_level = _LEVEL_ORDER.get(overall_level, 0)

    if actual_level >= fail_threshold:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Core scan logic (async)
# ---------------------------------------------------------------------------

async def _run_scan(content: str, filename: str, vuln_check: bool) -> dict:
    """Run the full scan pipeline and return a result dict."""
    from app.core.parser import ParseError, parse
    from app.core.risk_analyzer import analyze
    from app.core.validator import validate
    from app.core.vuln_checker import check_vulnerabilities

    try:
        doc = parse(content, filename=filename)
    except ParseError as exc:
        click.secho(f"Parse error: {exc}", fg="red", err=True)
        sys.exit(2)

    validation_result = validate(doc)

    vuln_results: dict = {}
    if vuln_check:
        try:
            vuln_results = await check_vulnerabilities(doc.components, enabled=True)
        except Exception as exc:
            click.secho(
                f"Warning: vulnerability check failed: {exc}", fg="yellow", err=True
            )

    risk_report = analyze(doc, vuln_results=vuln_results)

    # Count stats
    vulnerable_count = sum(
        1
        for comp in doc.components
        if _get_comp_vulns(comp, vuln_results)
    )
    invalid_count = sum(
        1
        for cv in validation_result.component_results
        if any(i.severity == "ERROR" for i in cv.issues)
    )

    # Build structured result
    components_out = []
    risk_map = {cr.component_name: cr for cr in risk_report.component_risks}
    validation_map = {cv.component_name: cv for cv in validation_result.component_results}

    for comp in doc.components:
        cr = risk_map.get(comp.name)
        cv = validation_map.get(comp.name)
        vulns = _get_comp_vulns(comp, vuln_results)
        components_out.append({
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "cpe": comp.cpe,
            "supplier": comp.supplier,
            "licenses": comp.licenses,
            "component_type": comp.component_type,
            "risk_level": cr.risk_level if cr else "LOW",
            "risk_score": cr.risk_score if cr else 0.0,
            "risk_factors": cr.factors if cr else [],
            "missing_fields": cv.missing_fields if cv else [],
            "vulnerabilities": vulns,
        })

    validation_issues_out = [
        {
            "severity": i.severity,
            "code": i.code,
            "message": i.message,
            "component_name": i.component_name,
        }
        for i in validation_result.issues
    ]

    return {
        "filename": filename,
        "sbom_format": doc.format,
        "format_version": doc.spec_version,
        "risk_level": risk_report.overall_risk_level,
        "risk_score": risk_report.overall_risk_score,
        "ntia_compliant": validation_result.ntia_compliant,
        "total_components": len(doc.components),
        "vulnerable_components": vulnerable_count,
        "invalid_components": invalid_count,
        "vuln_check_enabled": vuln_check,
        "summary": risk_report.summary,
        "components": components_out,
        "validation_issues": validation_issues_out,
    }


def _get_comp_vulns(comp, vuln_results: dict) -> list:
    """Look up vulnerabilities for a component."""
    if comp.purl and comp.purl in vuln_results:
        return vuln_results[comp.purl]
    if comp.version:
        key = f"{comp.name}@{comp.version}"
        if key in vuln_results:
            return vuln_results[key]
    return vuln_results.get(comp.name) or []


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _output_json(result: dict) -> None:
    """Print full scan result as JSON."""
    click.echo(json.dumps(result, indent=2, default=str))


def _output_text(result: dict) -> None:
    """Print a human-readable summary using rich."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
    except ImportError:
        click.secho(
            "rich is required for text output. Install it with: pip install rich",
            fg="red",
            err=True,
        )
        _output_json(result)
        return

    console = Console()

    risk_level = result.get("risk_level", "UNKNOWN")
    risk_colors = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "dark_orange",
        "CRITICAL": "red",
    }
    risk_color = risk_colors.get(risk_level, "white")

    # Header panel
    ntia_status = "[green]YES[/green]" if result.get("ntia_compliant") else "[red]NO[/red]"
    console.print(
        Panel(
            f"[bold]File:[/bold] {result.get('filename', '')}\n"
            f"[bold]Format:[/bold] {result.get('sbom_format', '')} "
            f"{result.get('format_version', '')}\n"
            f"[bold]Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}] "
            f"(score: {result.get('risk_score', 0):.1f})\n"
            f"[bold]NTIA Compliant:[/bold] {ntia_status}",
            title="[bold cyan]Verity SBOM Scan Result[/bold cyan]",
            border_style="cyan",
        )
    )

    # Summary statistics table
    summary_table = Table(title="Summary", box=box.SIMPLE, show_header=True)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Total Components", str(result.get("total_components", 0)))
    summary_table.add_row(
        "Vulnerable Components",
        f"[{'red' if result.get('vulnerable_components', 0) > 0 else 'green'}]"
        f"{result.get('vulnerable_components', 0)}[/]",
    )
    summary_table.add_row(
        "Invalid Components",
        f"[{'red' if result.get('invalid_components', 0) > 0 else 'green'}]"
        f"{result.get('invalid_components', 0)}[/]",
    )
    summary_table.add_row("Vulnerability Check", "Yes" if result.get("vuln_check_enabled") else "No")

    risk_dist = result.get("summary") or {}
    summary_table.add_row("LOW", str(risk_dist.get("LOW", 0)))
    summary_table.add_row("MEDIUM", str(risk_dist.get("MEDIUM", 0)))
    summary_table.add_row("HIGH", f"[dark_orange]{risk_dist.get('HIGH', 0)}[/dark_orange]")
    summary_table.add_row("CRITICAL", f"[red]{risk_dist.get('CRITICAL', 0)}[/red]")

    console.print(summary_table)

    # Validation issues
    issues = result.get("validation_issues") or []
    if issues:
        issues_table = Table(title="Validation Issues", box=box.SIMPLE)
        issues_table.add_column("Severity", style="bold", width=10)
        issues_table.add_column("Code", width=30)
        issues_table.add_column("Message")
        issues_table.add_column("Component")

        sev_style = {"ERROR": "red", "WARNING": "yellow", "INFO": "cyan"}
        for issue in issues:
            sev = issue.get("severity", "")
            style = sev_style.get(sev, "white")
            issues_table.add_row(
                f"[{style}]{sev}[/{style}]",
                issue.get("code", ""),
                issue.get("message", ""),
                issue.get("component_name") or "",
            )
        console.print(issues_table)

    # HIGH and CRITICAL components
    high_plus = [
        c for c in result.get("components") or []
        if _LEVEL_ORDER.get(str(c.get("risk_level", "")).upper(), 0) >= _LEVEL_ORDER["HIGH"]
    ]

    if high_plus:
        high_table = Table(title="HIGH and CRITICAL Components", box=box.SIMPLE)
        high_table.add_column("Name")
        high_table.add_column("Version")
        high_table.add_column("Risk Level", justify="center")
        high_table.add_column("Score", justify="right")
        high_table.add_column("Vulns", justify="right")
        high_table.add_column("Top Factor")

        for comp in high_plus:
            lvl = str(comp.get("risk_level", "")).upper()
            lvl_color = risk_colors.get(lvl, "white")
            factors = comp.get("risk_factors") or []
            top_factor = factors[0] if factors else ""
            high_table.add_row(
                comp.get("name", ""),
                comp.get("version") or "",
                f"[{lvl_color}]{lvl}[/{lvl_color}]",
                f"{comp.get('risk_score', 0):.1f}",
                str(len(comp.get("vulnerabilities") or [])),
                top_factor,
            )
        console.print(high_table)
    else:
        console.print("[green]No HIGH or CRITICAL components found.[/green]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
