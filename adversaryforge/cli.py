"""AdversaryForge CLI — run campaigns, inspect the substrate, and report.

    adversaryforge campaign            # run an attack campaign against the target
    adversaryforge status              # observability snapshot (the required questions)
    adversaryforge seeds               # list the seed library + coverage
    adversaryforge regress             # re-run the regression suite
    adversaryforge report              # (re)generate vulnerability reports
"""
from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from adversaryforge.config import get_settings
from adversaryforge.observability.store import Store
from adversaryforge.redteam.seeds import SeedLibrary

app = typer.Typer(add_completion=False, help="AdversaryForge — adversarial evaluation platform.")
console = Console()


@app.command()
def campaign(
    categories: str = typer.Option("", help="Comma-separated categories to target (default: all runnable)."),
    sweep: bool = typer.Option(True, help="Run all runnable seeds (vs. one orchestrator directive)."),
    limit: int = typer.Option(0, help="Cap seeds executed (0 = no cap)."),
):
    """Run an adversarial campaign against the configured target."""
    from adversaryforge.platform import run_campaign

    settings = get_settings()
    cats = [c.strip() for c in categories.split(",") if c.strip()] or None
    console.print(f"[bold]Target:[/bold] {settings.target_base_url}  "
                  f"[dim](llm={'yes' if settings.has_llm else 'no'}, "
                  f"session={'yes' if settings.has_session else 'no'})[/dim]")
    result = asyncio.run(run_campaign(settings=settings, categories=cats, sweep=sweep,
                                      limit=limit or None))
    console.print(f"\n[bold green]Campaign {result.run_id}[/bold green] "
                  f"vs {result.target_version} "
                  f"({'authenticated' if result.authenticated else 'unauthenticated'})")
    console.print(f"  directive: [dim]{result.directive_rationale}[/dim]")
    console.print(f"  attempts: {result.total}  outcomes: {result.by_outcome}")
    console.print(f"  [bold]successes: {result.successes}[/bold]  "
                  f"new confirmed exploits: {result.exploits_new}  "
                  f"partials mutated: {result.mutations_run}")


@app.command()
def status():
    """Print the observability snapshot the Orchestrator reads."""
    store = Store(get_settings().db_path)
    console.print("[bold]Coverage by category[/bold]")
    cov = store.coverage_by_category()
    if not cov:
        console.print("  [dim](no attempts yet)[/dim]")
    for cat, n in sorted(cov.items()):
        console.print(f"  {cat}: {n}")

    console.print("\n[bold]Pass/fail by category[/bold]")
    for cat, outs in sorted(store.passfail_rates().items()):
        console.print(f"  {cat}: {outs}")

    console.print("\n[bold]Open findings[/bold]  " + str(store.open_findings()))

    console.print("\n[bold]Resilience trend[/bold]")
    for row in store.resilience_trend()[-8:]:
        console.print(f"  {row['started_at'][:19]}  {row['target_version']}  "
                      f"success_rate={row['success_rate']}  ({row['successes']}/{row['total']})")

    console.print("\n[bold]Cost[/bold]  " + str(store.cost_summary()))


@app.command()
def seeds():
    """List the seed library grouped by category, with test-design roles."""
    lib = SeedLibrary.load()
    table = Table(title=f"Seed library — {len(lib.seeds)} cases, {len(lib.categories())} categories")
    table.add_column("id"); table.add_column("category"); table.add_column("role")
    table.add_column("auth"); table.add_column("title")
    for s in lib.seeds:
        cat = s.category if isinstance(s.category, str) else s.category.value
        table.add_row(s.id, cat, s.test_role, "🔒" if s.requires_auth else "🌐", s.title)
    console.print(table)


@app.command()
def regress():
    """Re-run the regression suite against the current target version."""
    from adversaryforge.harness.regression import run_regression

    settings = get_settings()
    result = asyncio.run(run_regression(settings=settings))
    gate = "[green]GREEN[/green]" if result.get("all_passed") else "[red]NOT GREEN[/red]"
    console.print(f"[bold]Regression[/bold] vs {result['target_version']} — gate {gate}")
    console.print(f"  {result['passed']}/{result['total']} passed · "
                  f"[red]{result['failed']} failed[/red] · "
                  f"{result.get('skipped', 0)} skipped · "
                  f"{result.get('errored', 0)} errored (inconclusive) · "
                  f"[red]{result['reappeared']} reappeared[/red]")
    _marks = {"passed": "✅", "failed": "❌", "skipped": "⏭️", "errored": "⚠️"}
    for row in result["details"]:
        mark = _marks.get(row.get("result", ""), "✅" if row["passed"] else "❌")
        console.print(f"  {mark} {row['case_id']} [{row['category']}] {row['note']}")


@app.command()
def report():
    """(Re)generate vulnerability reports from confirmed exploits."""
    from adversaryforge.agents.documentation import generate_all_reports

    settings = get_settings()
    n = generate_all_reports(settings=settings)
    console.print(f"[bold green]Generated/updated {n} vulnerability report(s)[/bold green] "
                  f"in reports/")


if __name__ == "__main__":
    app()
