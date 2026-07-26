"""
Governed MCP tool boundary — least privilege made structural.

Two tools, two very different trust levels:

  fetch_threat_intel(ref)              — READ-only egress. Fetches a threat
                                         writeup/CVE. In offline mode returns a
                                         fixture. This is the ONLY external
                                         capability the authoring flow may use.

  deploy_detection(bundle_dir, token,  — WRITE egress (push a rule to a SIEM).
                   approver)             REFUSES unless presented an approval
                                         token that verifies against the live
                                         bundle's gate decision + content hash.
                                         An approval for rule A cannot be
                                         replayed onto rule B.

The Foundry graph imports NEITHER tool. It cannot fetch and it cannot deploy —
those privileges live out-of-band in this server, exercised by a human operator
(see run.py --approve). That separation is the point: capability is held by the
harness, not the agent. Deploy here is a governed stub (writes a deploy-record)
so the whole thing stays offline; wiring a real Splunk/Elastic/Sentinel push is
a drop-in at the marked seam.
"""
from __future__ import annotations

import json
from pathlib import Path

from .governance import verify_approval
from .state import GateDecision

try:
    from fastmcp import FastMCP
    _mcp: "FastMCP | None" = FastMCP("detection-foundry-governed-tools")
except Exception:  # pragma: no cover - fastmcp optional for offline core
    _mcp = None


class EgressDenied(Exception):
    """Raised when a privileged egress action is attempted without authorization."""


# --------------------------------------------------------------------------- #
def fetch_threat_intel(ref: str, offline_fixture: dict | None = None) -> dict:
    """READ-only intel fetch. Allowlisted egress. Offline returns the fixture."""
    if offline_fixture is not None:
        return offline_fixture
    # SEAM: real implementation would GET an allowlisted CVE/KEV/vendor URL here.
    raise EgressDenied(f"live intel fetch for {ref!r} not enabled offline; provide offline_fixture")


# --------------------------------------------------------------------------- #
def deploy_detection(bundle_dir: str, token: str | None, approver: str) -> dict:
    """
    Human-gated WRITE egress. Refuses unless `token` verifies against THIS bundle's
    gate decision + content hash. This is the structural enforcement point.
    """
    bundle = Path(bundle_dir)
    proof = json.loads((bundle / "proof.json").read_text(encoding="utf-8"))
    gate = GateDecision(**proof["gate"])
    content_hash = proof["content_hash"]

    if gate.requires_human and not verify_approval(token, gate, content_hash, approver):
        raise EgressDenied(
            f"deploy REFUSED: gate tier {gate.tier} requires a valid human approval token "
            f"bound to hash {content_hash[:23]}… (approver={approver!r}). "
            "The authoring agent cannot mint this token."
        )

    # SEAM: real push to SIEM would happen here. Offline: write a deploy record.
    record = {
        "deployed_rule": str(bundle / "rule.yml"),
        "content_hash": content_hash,
        "approver": approver,
        "gate_tier": gate.tier,
        "note": "OFFLINE deploy-record; wire a real SIEM connector at this seam.",
    }
    (bundle / "deploy-record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


# --------------------------------------------------------------------------- #
# Register with FastMCP when available, so this doubles as a real MCP server.
if _mcp is not None:  # pragma: no cover
    _mcp.tool(fetch_threat_intel)
    _mcp.tool(deploy_detection)


def get_server():
    if _mcp is None:
        raise RuntimeError("fastmcp not installed; governed tools still callable as plain functions")
    return _mcp
