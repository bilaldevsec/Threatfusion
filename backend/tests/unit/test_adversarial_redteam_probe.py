"""The agy probe defeats five bad requests on a temporary database."""

from __future__ import annotations

from pathlib import Path

from scripts.run_adversarial_redteam_probe import run_isolated_audit


def test_isolated_probe_defeats_five_bypasses_without_the_live_database(tmp_path: Path) -> None:
    audit = tmp_path / "agy-audit.json"
    assert run_isolated_audit(audit) == 0
    text = audit.read_text(encoding="utf-8")
    assert "5/5 Boundaries Held" in text
