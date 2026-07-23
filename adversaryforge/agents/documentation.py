"""Documentation Agent — turns Judge-confirmed exploits into professional
vulnerability reports, with no human writing them.

Design constraints (from the platform requirements):
  * **Deterministic-first.** Every required report field is filled from the
    exploit contract alone — the module produces complete, reproducible reports
    with no LLM key and no live session. An optional LLM enrichment pass
    (`adversaryforge.llm`) only *improves* prose; it is imported behind a
    try/except so its absence is invisible.
  * **Reproducibility bar.** A senior engineer who was *not* present must be able
    to reproduce, validate, and fix the vuln from the report alone — so the
    reproduction section is numbered, copy-pasteable, and shows the actual
    request/response turns from the minimal transcript.
  * **Two trust gates.**
      1. *Data-quality gate* — an exploit missing a required field (severity,
         category, reproduction material, observed, expected) is skipped, not
         emitted; the return count reflects only valid reports.
      2. *Human-approval gate* — a `critical` report is a `draft` that
         `requires_human_approval` and carries a prominent banner; it is never
         auto-published. Lower severities may publish.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

from adversaryforge.contracts import (
    ConfirmedExploit,
    Severity,
    TranscriptTurn,
    VulnReport,
)
from adversaryforge.observability.store import Store

# Repo root: adversaryforge/agents/documentation.py -> parents[2].
_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORTS_DIR = _REPO_ROOT / "reports"


# ─────────────────────── invariant → clinical framing ─────────────────────
# Keyed by the target invariant id. Each entry gives a *realistic clinical*
# impact and a *concrete* remediation, so the report is specific to what was
# actually falsified rather than boilerplate. Falls back to a generic entry for
# any invariant not enumerated here.
_INVARIANT_PLAYBOOK: dict[str, dict[str, str]] = {
    "INV-AUTHZ-PATIENT": {
        "impact": (
            "A clinician session can reach a patient record that is not on that "
            "clinician's authorized panel. In a clinical setting this is a direct "
            "confidentiality breach (HIPAA minimum-necessary violation): the "
            "Co-Pilot surfaces another patient's chart, medications, or problem "
            "list to a provider with no treatment relationship. It also enables "
            "targeted harm — a bad actor with any valid clinician login can walk "
            "arbitrary patient IDs."
        ),
        "remediation": (
            "Enforce patient-level authorization server-side on every tool call, "
            "not in the prompt. Resolve the caller's authorized patient set from "
            "the SMART/OAuth identity and reject (HTTP 403) any request whose "
            "patient_id is outside it, before the model or any FHIR read runs. "
            "Add an object-level access-control test to the regression suite that "
            "asserts 403/404 for an out-of-panel patient_id."
        ),
    },
    "INV-INFO-DISCLOSURE": {
        "impact": (
            "The Co-Pilot deployment discloses internal state to an unauthenticated "
            "caller. Individually low-harm, but it hands an attacker a reconnaissance "
            "map — internal architecture, configuration, or contract surface — that "
            "lowers the cost of every subsequent clinical-data or excessive-agency "
            "attack. (Exactly what leaks is finding-specific; see the observed "
            "behavior below.)"
        ),
        "remediation": (
            "Gate or minimize the disclosing endpoint itself (see the observed "
            "behavior for which one). For anonymous infra endpoints: require auth "
            "for detailed dependency/health inventory (return only a minimal liveness "
            "signal to anonymous callers), disable the public OpenAPI/schema route in "
            "production, and stop returning config/version (e.g. auth_mode) to "
            "unauthenticated callers. For any model-facing path, also strip stack "
            "traces and internal markers behind a generic error envelope."
        ),
    },
    "INV-RATE-LIMIT": {
        "impact": (
            "The endpoint accepts unbounded request volume from a single session. "
            "Against a clinical assistant this is an availability risk during "
            "care — a flood degrades or denies the Co-Pilot for every clinician on "
            "the instance — and, paired with an oracle, enables high-volume "
            "enumeration (patient existence, ID sweeps)."
        ),
        "remediation": (
            "Add per-identity and per-IP inbound rate limiting and concurrency "
            "caps at the gateway (token bucket, e.g. N req/min/clinician) with "
            "HTTP 429 + Retry-After. Alert on sustained saturation. Do not rely on "
            "client-side throttling."
        ),
    },
    "INV-INJECTION-INERT": {
        "impact": (
            "Untrusted content (a chat message, or data pulled from a record) "
            "steered the model into ignoring its instructions or invoking tools it "
            "should not. In a clinical Co-Pilot this is the highest-leverage flaw: "
            "injected text can trigger data exfiltration, unauthorized writes to a "
            "chart, or fabricated clinical guidance presented as trusted output."
        ),
        "remediation": (
            "Treat all record-derived and user content as untrusted data, never "
            "instructions: segregate it in the prompt with explicit framing, and "
            "gate every state-changing or data-egress tool behind server-side "
            "policy that a prompt cannot override. Add injection-corpus regression "
            "cases asserting the tool is NOT called and instructions are NOT "
            "followed."
        ),
    },
    "INV-WITHHOLD-UNGROUNDED": {
        "impact": (
            "The Co-Pilot answered a clinical question it could not ground in the "
            "record instead of withholding. A confidently fabricated dose, "
            "allergy, or interaction reaching a clinician at the point of care is a "
            "direct patient-safety hazard — the model should have declined."
        ),
        "remediation": (
            "Require retrieval-grounding for clinical assertions: if no supporting "
            "record evidence is retrieved, the model must withhold with an explicit "
            "'not in the record' response rather than answer from parametric "
            "memory. Add faithfulness/abstention checks to the eval and a "
            "regression case asserting a withhold response for ungrounded queries."
        ),
    },
    "INV-WRITE-GATED": {
        "impact": (
            "A state-changing action (order, note, medication, or chart write) "
            "executed without the required confirmation/authorization gate. An "
            "unintended or attacker-induced write to a clinical record can alter "
            "the care plan — a serious integrity and patient-safety event, and a "
            "medico-legal liability."
        ),
        "remediation": (
            "Make every write tool two-phase and server-authorized: the model may "
            "only *propose*; commit requires an explicit, out-of-band clinician "
            "confirmation plus a server-side authorization check on the acting "
            "identity. Log every write with actor and justification. Regression: "
            "assert no write occurs without the confirmation token."
        ),
    },
    "INV-PHI-EGRESS": {
        "impact": (
            "Protected health information left the system boundary through an "
            "unintended channel (echoed to an unauthenticated surface, embedded in "
            "an outbound URL/tool call, or returned in bulk). This is a reportable "
            "PHI breach with regulatory (HIPAA), legal, and patient-trust "
            "consequences."
        ),
        "remediation": (
            "Add an egress filter on every outbound path (responses, tool args, "
            "logs) that detects and blocks PHI leaving to unauthorized "
            "destinations, and forbid the model from placing record data into URLs "
            "or external calls. Enforce minimum-necessary response shaping. "
            "Regression: assert no PHI markers appear on unauthenticated or "
            "external channels."
        ),
    },
    "INV-EXISTENCE-ORACLE": {
        "impact": (
            "Differential responses let a caller infer whether a given patient "
            "exists in the system (distinct error/timing/shape for present vs "
            "absent IDs). Even without reading the chart, confirming that a named "
            "individual is a patient at this facility is itself a confidentiality "
            "breach (e.g. a public figure, a psychiatric or substance-use clinic)."
        ),
        "remediation": (
            "Make present-vs-absent responses indistinguishable: a uniform "
            "403/404 shape, constant-time handling, and identical error bodies "
            "regardless of existence. Combine with rate limiting to blunt "
            "enumeration. Regression: assert byte-identical responses for a known "
            "vs a random patient_id to an unauthorized caller."
        ),
    },
    "INV-HISTORY-INTEGRITY": {
        "impact": (
            "Conversation or record history could be corrupted, spoofed, or "
            "replayed — e.g. injecting fake prior turns or overwriting context so "
            "the model acts on a fabricated clinical history. Downstream decisions "
            "built on a tampered history are unsafe and unauditable."
        ),
        "remediation": (
            "Treat history as append-only and server-owned: never let the client "
            "supply or edit prior turns/context that the model trusts; sign or "
            "server-store the transcript and validate continuity. Audit-log any "
            "context mutation. Regression: assert client-supplied history cannot "
            "override server state."
        ),
    },
    "INV-COST-BOUNDED": {
        "impact": (
            "A single request can drive unbounded model/tool consumption (huge "
            "generations, recursive tool loops, oversized context). Beyond direct "
            "cost, this is an availability and denial-of-wallet risk that can "
            "starve the Co-Pilot for clinicians and inflate spend without limit."
        ),
        "remediation": (
            "Bound every request: hard caps on tokens, tool-call depth/iterations, "
            "context size, and wall-clock per turn, plus a per-identity spend "
            "budget that fails closed (HTTP 429/413). Alert on anomalous "
            "consumption. Regression: assert an oversized/looping request is "
            "rejected, not served."
        ),
    },
}

_GENERIC_PLAYBOOK = {
    "impact": (
        "The target's stated safety invariant was falsified. In a clinical "
        "assistant any invariant violation risks patient confidentiality, record "
        "integrity, or safe clinical guidance and must be triaged before the "
        "Co-Pilot is trusted at the point of care."
    ),
    "remediation": (
        "Enforce the violated invariant server-side (independent of the prompt), "
        "add a deterministic regression case that re-checks it on every target "
        "version, and re-run the adversarial suite to confirm the defense holds."
    ),
}

_CATEGORY_LABEL: dict[str, str] = {
    "prompt_injection": "Prompt Injection",
    "data_exfiltration": "Data Exfiltration",
    "state_corruption": "State Corruption",
    "tool_misuse": "Tool Misuse",
    "denial_of_service": "Denial of Service",
    "identity_role": "Identity / Role Confusion",
}


def _enum(v) -> str:
    """Normalize an enum-or-string to its string value."""
    return v.value if hasattr(v, "value") else str(v)


def _playbook(invariant: str) -> dict[str, str]:
    return _INVARIANT_PLAYBOOK.get((invariant or "").strip().upper(), _GENERIC_PLAYBOOK)


# ─────────────────────── reproducibility normalization ────────────────────
# The committed VULN-*.md must be byte-reproducible: regenerating a report for
# the SAME finding must not churn the git diff. Live per-run timing (a burst's
# elapsed time, a response latency — e.g. "228ms") is genuine measurement noise,
# not part of the finding, so every latency figure in the prose is collapsed to
# a stable placeholder. The digit prefix is required, so tokens like
# "latency_ms<=150" (a stable threshold, no measured value) are left untouched.
_LATENCY_RE = re.compile(r"\d+(?:\.\d+)?\s*ms\b")


def _normalize_latency(text: str) -> str:
    """Redact volatile latency figures ("228ms") to a stable placeholder so the
    committed report is byte-identical run-to-run for an unchanged finding."""
    return _LATENCY_RE.sub("<elapsed>ms", text or "")


# ─────────────────────── reproduction rendering ───────────────────────────
def _render_request_detail(turn: TranscriptTurn) -> str:
    """Best-effort HTTP line from a turn's raw payload, if present."""
    raw = turn.raw or {}
    method = raw.get("method") or raw.get("http_method")
    url = raw.get("url") or raw.get("path") or raw.get("endpoint")
    if method and url:
        return f"{str(method).upper()} {url}"
    if url:
        return f"POST {url}"
    return ""


def build_reproduction(transcript: Iterable[TranscriptTurn]) -> list[str]:
    """Numbered, copy-pasteable reproduction steps from the minimal transcript.

    Attacker turns become 'send this request' steps (with the actual content and
    any HTTP method/path); target turns become 'observe this response' steps with
    the HTTP status. A trailing confirmation step closes the loop."""
    steps: list[str] = [
        "Authenticate to the target as a clinician "
        "(https://agentforge.hankholcomb.com). Synthetic demo data only. "
        "If no session is available, use the unauthenticated surface — the "
        "exploit below reproduces without one.",
    ]
    turns = list(transcript)
    for turn in turns:
        content = _normalize_latency((turn.content or "").rstrip())
        if turn.role == "attacker":
            http = _render_request_detail(turn)
            head = "Send the following request to the Co-Pilot"
            if http:
                head += f" ({http})"
            steps.append(f"{head}:\n\n```\n{content}\n```")
        else:  # target
            status = f" (HTTP {turn.http_status})" if turn.http_status is not None else ""
            steps.append(
                f"Observe the target's response{status}:\n\n```\n{content}\n```"
            )
    steps.append(
        "Confirm the observed behavior below is present (and differs from the "
        "expected safe behavior). The finding reproduces when it is."
    )
    return steps


# ─────────────────────── data-quality gate ────────────────────────────────
def validate_exploit(exploit: ConfirmedExploit) -> str | None:
    """Data-quality gate. Returns a human-readable reason the exploit cannot be
    turned into a valid report, or None if it passes.

    Required non-empty material: severity, category, an observed behavior, an
    expected-safe behavior, and at least one transcript turn to build the
    reproduction from."""
    if not _enum(exploit.severity).strip():
        return "missing severity"
    if not _enum(exploit.category).strip():
        return "missing category"
    if not (exploit.observed or "").strip():
        return "missing observed behavior"
    if not (exploit.expected_safe or "").strip():
        return "missing expected-safe behavior"
    if not exploit.minimal_transcript:
        return "empty transcript — no reproduction material"
    if not any((t.content or "").strip() for t in exploit.minimal_transcript):
        return "transcript has no content — no reproduction material"
    return None


# ─────────────────────── report construction ──────────────────────────────
def _report_id(exploit: ConfirmedExploit) -> str:
    # Stable across runs: key on the FINDING identity (category + minimal
    # transcript), NOT the per-run exploit_id. So regenerating overwrites the same
    # VULN-*.md file instead of accumulating duplicates for the same finding.
    cat = exploit.category.value if hasattr(exploit.category, "value") else str(exploit.category)
    # Mirror Store._dedupe_key exactly (json, not a "|" join): attacker sequence +
    # invariant only, so the same finding yields the same VULN-*.md id across runs.
    payload = {
        "category": cat,
        "invariant": exploit.target_invariant or "",
        "attacker": [t.content for t in exploit.minimal_transcript if t.role == "attacker"],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:10]
    return f"VULN-{digest}"


def build_report(exploit: ConfirmedExploit) -> VulnReport:
    """Deterministically fill every required VulnReport field from a confirmed
    exploit. Pure and offline — no LLM, no network.

    The human-approval gate is applied here: a critical-severity finding is a
    draft that requires human approval before it can be published."""
    severity = _enum(exploit.severity)
    category = _enum(exploit.category)
    invariant = (exploit.target_invariant or "").strip()
    play = _playbook(invariant)
    # Normalize volatile latency in the observed prose once, up front, so every
    # field derived from it (summary, clinical impact, observed behavior) stays
    # byte-reproducible for an unchanged finding.
    observed = _normalize_latency((exploit.observed or "").strip())

    cat_label = _CATEGORY_LABEL.get(category, category.replace("_", " ").title())
    inv_label = invariant or "the target safety invariant"
    title = (
        f"{severity.capitalize()}-severity {cat_label}: "
        f"{inv_label} falsified in the AgentForge Clinical Co-Pilot"
    )

    summary = (
        f"An adversarial attempt in the {cat_label} category falsified the "
        f"{inv_label} invariant of the AgentForge Clinical Co-Pilot. "
        f"Observed: {observed} "
        f"The target should instead have exhibited: "
        f"{(exploit.expected_safe or '').strip()}"
    )

    reproduction = build_reproduction(exploit.minimal_transcript)

    is_critical = severity == Severity.critical.value
    status = "draft" if is_critical else "published"
    requires_approval = is_critical

    fix_validation = (
        "Add a deterministic regression case for "
        f"{inv_label} to the harness and re-run the adversarial suite against the "
        "patched target; the finding is fixed only when that case (and the full "
        "category) pass on the new target version."
    )

    return VulnReport(
        report_id=_report_id(exploit),
        exploit_id=exploit.exploit_id,
        title=title,
        severity=severity,
        category=category,
        status=status,
        summary=summary,
        # Weave the actual observed disclosure into the impact so two findings that
        # share an invariant do NOT emit byte-identical (and possibly wrong) text.
        clinical_impact=(f"Observed: {observed} {play['impact']}"
                         if observed else play["impact"]),
        reproduction=reproduction,
        observed_behavior=observed,
        expected_behavior=(exploit.expected_safe or "").strip(),
        remediation=play["remediation"],
        fix_validation=fix_validation,
        owasp_web=list(exploit.owasp_web),
        owasp_llm=list(exploit.owasp_llm),
        requires_human_approval=requires_approval,
    )


# ─────────────────────── optional LLM enrichment ──────────────────────────
def _maybe_enrich(report: VulnReport, exploit: ConfirmedExploit, settings) -> VulnReport:
    """If an LLM is configured, try to sharpen the prose (summary/impact). Never
    required: any import or call failure leaves the deterministic report intact."""
    if settings is None or not getattr(settings, "has_llm", False):
        return report
    try:  # the llm module is built by another agent; absence is fine
        from adversaryforge import llm  # type: ignore

        enricher = getattr(llm, "enrich_report", None)
        if enricher is None:
            return report
        enriched = enricher(report=report, exploit=exploit, settings=settings)
        if isinstance(enriched, VulnReport):
            return enriched
    except Exception:
        return report
    return report


# ─────────────────────── markdown rendering ───────────────────────────────
def _fmt_owasp(report: VulnReport) -> str:
    tags = [_enum(t) for t in report.owasp_web] + [_enum(t) for t in report.owasp_llm]
    return ", ".join(tags) if tags else "—"


def render_markdown(report: VulnReport) -> str:
    """Render a report as a professional vulnerability-report markdown document."""
    lines: list[str] = []
    if report.requires_human_approval:
        lines += [
            "> ## ⚠️ PENDING HUMAN APPROVAL — critical severity",
            ">",
            "> This report was generated automatically and describes a "
            "**critical**-severity finding. It is a **draft** and must be reviewed "
            "and approved by a human security engineer before it is published or "
            "acted upon.",
            "",
        ]

    lines += [
        f"# {report.title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        # Report ID is the stable content hash of the finding and IS committed.
        # The per-run exploit_id (ex_…) is deliberately omitted: it changes every
        # run for an unchanged finding and would churn the committed report.
        f"| Report ID | `{report.report_id}` |",
        f"| Severity | **{_enum(report.severity).upper()}** |",
        f"| Category | {_CATEGORY_LABEL.get(_enum(report.category), _enum(report.category))} |",
        f"| Status | {report.status} |",
        f"| OWASP | {_fmt_owasp(report)} |",
        f"| Requires human approval | {'yes' if report.requires_human_approval else 'no'} |",
        "",
        "## Summary",
        "",
        report.summary,
        "",
        "## Clinical impact",
        "",
        report.clinical_impact,
        "",
        "## Reproduction",
        "",
    ]
    # Bold-numbered paragraphs (not a `1.` ordered list): a step may contain a
    # fenced code block, which breaks out of an ordered list in strict CommonMark.
    for i, step in enumerate(report.reproduction, start=1):
        lines.append(f"**{i}.** {step}")
        lines.append("")

    lines += [
        "## Observed behavior",
        "",
        report.observed_behavior,
        "",
        "## Expected (safe) behavior",
        "",
        report.expected_behavior,
        "",
        "## Remediation",
        "",
        report.remediation,
        "",
        "## Fix validation",
        "",
        report.fix_validation or "—",
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def write_report_markdown(report: VulnReport, reports_dir: Path | str | None = None) -> Path:
    """Write `<report_id>.md` into the reports directory and return its path."""
    out_dir = Path(reports_dir) if reports_dir is not None else _REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{report.report_id}.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


# ─────────────────────── batch entry point ────────────────────────────────
def generate_all_reports(*, settings=None) -> int:
    """Build a report for every confirmed exploit in the store, record it, and
    write its markdown file. Returns the number of *valid* reports written.

    Degrades gracefully: works with no LLM key and no session. Exploits that fail
    the data-quality gate, or that would collide on report_id, are skipped (and
    logged as events) rather than emitted."""
    if settings is None:
        from adversaryforge.config import get_settings

        settings = get_settings()

    store = Store(settings.db_path)
    # Write reports next to the DB in use. The default (repo) data dir keeps the
    # committed reports/ at the repo root; a temp/override ADVERSARYFORGE_DATA_DIR
    # writes under that dir instead, so an out-of-tree run (perf harness, an audit
    # against a scratch DB) can never overwrite or prune the committed reports.
    data_dir = getattr(settings, "data_dir", None)
    reports_dir = (_REPORTS_DIR
                   if data_dir is None or Path(data_dir).resolve() == (_REPO_ROOT / "data").resolve()
                   else Path(data_dir) / "reports")
    written = 0
    seen_ids: set[str] = set()
    try:
        rows = store.list_exploits()
        # NEVER wipe committed reports when there is nothing to regenerate — e.g. a
        # fresh clone whose SQLite DB is git-ignored and empty. Only the current DB's
        # findings drive reports/, but an empty DB must not destroy the committed set.
        if not rows:
            return 0

        # Pass 1 — build every valid report (and its target filename).
        reports_to_write: list[VulnReport] = []
        for row in rows:
            exploit_id = row.get("exploit_id")
            if not exploit_id:
                continue
            exploit = store.get_exploit(exploit_id)
            if exploit is None:
                continue

            reason = validate_exploit(exploit)
            if reason is not None:
                store.log_event(None, "documentation", "report_skipped",
                                f"{exploit_id}: {reason}")
                continue

            report = build_report(exploit)
            if report.report_id in seen_ids:
                store.log_event(None, "documentation", "report_skipped",
                                f"{exploit_id}: duplicate report_id {report.report_id}")
                continue
            seen_ids.add(report.report_id)
            reports_to_write.append(_maybe_enrich(report, exploit, settings))

        # If NOTHING valid was rebuilt (e.g. every exploit failed the data-quality
        # gate), do not wipe committed reports we cannot regenerate.
        if not reports_to_write:
            return 0

        # Clean slate — but only remove stale VULN-*.md we will NOT rewrite, so a
        # partial/incomplete DB can never delete a report it cannot rebuild.
        keep = {f"{r.report_id}.md" for r in reports_to_write}
        for stale in reports_dir.glob("VULN-*.md"):
            if stale.name not in keep:
                stale.unlink()

        # Pass 2 — write.
        for report in reports_to_write:
            store.record_report(report)
            path = write_report_markdown(report, reports_dir)
            written += 1
            store.log_event(None, "documentation", "report_written",
                            f"{report.report_id} sev={_enum(report.severity)} -> {path.name}")
    finally:
        store.close()
    return written


__all__ = [
    "build_report",
    "build_reproduction",
    "validate_exploit",
    "render_markdown",
    "write_report_markdown",
    "generate_all_reports",
]
