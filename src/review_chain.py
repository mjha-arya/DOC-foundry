"""
The REVIEW CHAIN — a linear, stakeholder-review detection pipeline.

    ingest → extract → telemetry → profile
        → blue: DRAFT v1
        → RED TEAM review
        → blue: REVISION v2
        → SOC LEAD review
        → blue: FINAL v3
        → package

One pass, no loop, no verdict. Each reviewer sees the current rule, returns written
findings, and Blue revises against them — recording which finding each edit answers.
The deliverable is the final rule plus the full trail.

What this is NOT: the adversarial proof loop in `graph.py`. Nothing here executes the
rule against telemetry, counts false positives, or scores coverage. The packaged
output states that in one sentence at the top, because a reviewed rule that looks
finished is exactly the thing a reader will assume was tested.
"""
from __future__ import annotations

import json
import re
from functools import partial
from pathlib import Path

from langgraph.graph import END, START, StateGraph

from . import agents, review_agents
from .providers import LLMProvider
from .review_state import ReviewChainState, ReviewPackage

_OUT = Path(__file__).resolve().parent.parent / "Outputs"


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (s[:58] or "detection").strip("-")


# --------------------------------------------------------------------------- #
# Packaging — the final rule + the human-readable review history.
# --------------------------------------------------------------------------- #
def _render_history(pkg: ReviewPackage) -> str:
    t = pkg.threat
    L: list[str] = [
        f"# {pkg.final_rule.title if pkg.final_rule else t.title}",
        "",
        f"> **{pkg.disclaimer}**",
        "",
        "## Threat",
        "",
        f"**{t.title}**",
        "",
        t.summary,
        "",
        f"- ATT&CK: {', '.join(t.attack_techniques) or 'n/a'}",
        f"- Platforms: {', '.join(t.platforms) or 'n/a'}",
        f"- Source: `{t.source_ref}`",
        "",
        "## Telemetry the chain was fought on",
        "",
        f"- Log source: `{pkg.telemetry.category}`"
        + (f" · product `{pkg.telemetry.product}`" if pkg.telemetry.product else ""),
        f"- Fields available: `{'`, `'.join(pkg.telemetry.fields) or 'n/a'}`",
        "",
        "## How the rule evolved",
        "",
    ]

    # Interleave: version → the review of that version → the next version.
    reviews_by_version: dict[int, list] = {}
    for r in pkg.reviews:
        reviews_by_version.setdefault(r.reviews_version, []).append(r)

    for v in pkg.versions:
        L += [f"### v{v.version} — {v.label}", ""]
        if v.author_note:
            L += [f"*{v.author_note}*", ""]
        if v.changes:
            L += ["| Finding | What changed | Why |", "|---|---|---|"]
            for c in v.changes:
                what = c.what_changed.replace("|", "\\|")
                why = c.why.replace("|", "\\|")
                L.append(f"| `{c.finding_id}` | {what} | {why} |")
            L.append("")
        L += ["```yaml", v.yaml_text.strip(), "```", ""]

        for review in reviews_by_version.get(v.version, []):
            L += [f"### ⟶ {review.reviewer_label}", ""]
            if review.verdict_line:
                L += [f"> {review.verdict_line}", ""]
            if not review.findings:
                L += ["*No findings returned.*", ""]
            for f in review.findings:
                L += [
                    f"**`{f.id}` · {f.severity.upper()} — {f.title}**",
                    "",
                    f"{f.detail}" if f.detail else "",
                    f"**Asks for:** {f.ask}" if f.ask else "",
                    "",
                ]

    L += [
        "## Final rule",
        "",
        "```yaml",
        (pkg.final_rule.yaml_text.strip() if pkg.final_rule else ""),
        "```",
        "",
        "---",
        "",
        f"*Authored and reviewed by role-specialised agents (`{pkg.mode}`). "
        f"{pkg.disclaimer}*",
    ]
    return "\n".join(x for x in L if x is not None)


def node_package(state: ReviewChainState) -> dict:
    versions = state.get("versions", [])
    final = versions[-1] if versions else None
    pkg = ReviewPackage(
        threat=state["threat"],
        telemetry=state["telemetry"],
        versions=versions,
        reviews=state.get("reviews", []),
        final_rule=final,
        mode=state.get("mode", "claude"),
    )
    pkg.history_md = _render_history(pkg)

    out_dir = _OUT / _slug(final.title if final else state["threat"].title)
    out_dir.mkdir(parents=True, exist_ok=True)
    if final:
        (out_dir / "final-rule.yml").write_text(final.yaml_text.strip() + "\n", encoding="utf-8")
    (out_dir / "review-history.md").write_text(pkg.history_md, encoding="utf-8")
    (out_dir / "review.json").write_text(
        json.dumps(pkg.model_dump(mode="json"), indent=2, default=str), encoding="utf-8"
    )

    return {
        "package": pkg,
        "package_dir": str(out_dir),
        "log": [f"[package] {len(versions)} version(s), "
                f"{sum(len(r.findings) for r in pkg.reviews)} finding(s) → {out_dir}"],
    }


# --------------------------------------------------------------------------- #
def build_chain(provider: LLMProvider):
    """Compile the linear review chain with the provider bound into the LLM seats."""
    g = StateGraph(ReviewChainState)

    g.add_node("ingest", partial(agents.ingest, provider=provider))
    g.add_node("extract", partial(agents.extract_behaviors, provider=provider))
    g.add_node("telemetry", partial(agents.build_corpus, provider=provider))
    g.add_node("profile", review_agents.build_profile)
    g.add_node("draft", partial(review_agents.blue_draft, provider=provider))
    g.add_node("red_review", partial(review_agents.red_review, provider=provider))
    g.add_node("revise", partial(review_agents.blue_revise_after_red, provider=provider))
    g.add_node("soc_review", partial(review_agents.soc_review, provider=provider))
    g.add_node("final", partial(review_agents.blue_final_after_soc, provider=provider))
    g.add_node("package", node_package)

    for a, b in [
        (START, "ingest"), ("ingest", "extract"), ("extract", "telemetry"),
        ("telemetry", "profile"), ("profile", "draft"), ("draft", "red_review"),
        ("red_review", "revise"), ("revise", "soc_review"), ("soc_review", "final"),
        ("final", "package"), ("package", END),
    ]:
        g.add_edge(a, b)

    return g.compile()


def run(threat_text: str, provider: LLMProvider) -> ReviewPackage:
    """Run the chain end-to-end and return the package (CLI / test entry point)."""
    app = build_chain(provider)
    state = app.invoke(
        {
            "raw_threat": threat_text,
            "source_type": "writeup",
            "source_ref": threat_text[:60],
            "mode": getattr(provider, "mode", "claude"),
            "versions": [],
            "reviews": [],
            "log": [],
        },
        config={"recursion_limit": 40},
    )
    return state["package"]
