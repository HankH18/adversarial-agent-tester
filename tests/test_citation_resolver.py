"""Citation-resolver guard — `path.py:NNN` cites in the docs must hit live code.

The deliverable docs pin claims to specific source spans — "the info-barrier view
is built at `adversaryforge/agents/judge.py:39-59`". When the code moves and the
doc's line numbers do not, the citation silently points at the wrong span, a blank
line, or a file that has since been renamed. This exact drift has bitten
`AS_BUILT.md` repeatedly; it is invisible to a human skim and to every other test.

This guard re-resolves every in-repo `path.py:NNN[-MMM]` citation against the tree
at test time and fails if the file is gone, the range runs past end-of-file, or the
start line is blank (a cite that lands on whitespace is stale). The regex is
deliberately narrow — it only matches paths rooted at this repo's own source dirs
(`adversaryforge/`, `tests/`, `scripts/`, `contracts/`), so prose and citations
into the *separate* target repo (`api/app.py:99-212`) never false-trigger.

Fully offline: no ANTHROPIC_API_KEY, no session cookie, no network.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Conservative on purpose: a citation must be rooted at one of THIS repo's source
# dirs and end in `.py:NNN` (optionally a `:NNN-MMM` range). That excludes bare
# prose, un-lined file mentions, and `api/app.py:99` cites into the target repo.
_CITATION_RX = re.compile(
    r"\b((?:adversaryforge|tests|scripts|contracts)/[\w./-]+\.py):(\d+)(?:-(\d+))?"
)


def _iter_doc_files() -> list[Path]:
    """Every markdown doc under `docs/**` plus the repo-root `*.md`, minus anything
    quarantined under an `archive/` path segment (superseded history)."""
    docs: list[Path] = []
    seen: set[Path] = set()
    for path in sorted(_REPO_ROOT.glob("*.md")):
        if path.is_file():
            docs.append(path)
            seen.add(path)
    for path in sorted(_REPO_ROOT.glob("docs/**/*.md")):
        if "archive" in path.relative_to(_REPO_ROOT).parts:
            continue
        if path.is_file() and path not in seen:
            docs.append(path)
    return docs


def _citations() -> list[tuple[Path, str, int, int]]:
    """`(doc, cited_path, start, end)` for every in-repo code citation in the docs;
    `end == start` when the cite names a single line rather than a range."""
    out: list[tuple[Path, str, int, int]] = []
    for doc in _iter_doc_files():
        for m in _CITATION_RX.finditer(doc.read_text(encoding="utf-8")):
            start = int(m.group(2))
            end = int(m.group(3)) if m.group(3) else start
            out.append((doc, m.group(1), start, end))
    return out


def test_doc_citations_resolve():
    """Every `path.py:NNN[-MMM]` cite in a live doc resolves: the file exists, the
    end line is within the file, and the start line is a real (non-blank) line.

    All drifts are collected into one list so a single run reports every stale
    citation at once — fix the doc, never this guard."""
    failures: list[str] = []
    for doc, rel_path, start, end in _citations():
        span = f"{rel_path}:{start}" if end == start else f"{rel_path}:{start}-{end}"
        where = f"{doc.relative_to(_REPO_ROOT)}: {span}"
        cited = _REPO_ROOT / rel_path
        if not cited.is_file():
            failures.append(f"{where} -> file does not exist")
            continue
        lines = cited.read_text(encoding="utf-8").splitlines()
        if end > len(lines):
            failures.append(f"{where} -> end line {end} past end of file ({len(lines)} lines)")
            continue
        if start < 1:
            failures.append(f"{where} -> start line {start} is < 1")
            continue
        if lines[start - 1].strip() == "":
            failures.append(f"{where} -> start line {start} is blank (stale citation)")
    assert not failures, (
        "stale doc->code citations (fix the doc, not this test):\n" + "\n".join(failures)
    )


def test_docs_contain_resolvable_citations():
    """Sanity anchor: the corpus really does carry in-repo code citations, so the
    resolver above can never pass merely because the regex quietly matched nothing."""
    assert _citations(), "no `path.py:NNN` citations found — the regex may have gone stale"
