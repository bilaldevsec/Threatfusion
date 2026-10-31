"""Gemini copilot selection stays local when the key, network, or budget is absent."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    verify_explanation_groundedness,
)
from threatfusion.advisory.gemini_client import (
    SOC_COPILOT_SYSTEM_PROMPT,
    GeminiAdvisoryCallable,
    GeminiAdvisoryConfig,
    GeminiAdvisoryUnavailableError,
    advisory_provider_status,
    build_grounded_gemini_prompt,
    resolve_gemini_model,
)
from threatfusion.api.live_soc_console import answer_mitre_copilot


def test_unset_model_stays_gemini_2_5_flash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert GeminiAdvisoryConfig().model_name == "gemini-2.5-flash"
    assert resolve_gemini_model() == "gemini-2.5-flash"
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.0-flash")
    assert resolve_gemini_model() == "gemini-2.0-flash"
    assert GeminiAdvisoryCallable().config.model_name == "gemini-2.0-flash"


def test_prompt_keeps_the_system_sentence_and_the_debrief_rules() -> None:
    bundle = AdvisoryEvidenceBundle(
        candidate_id="cand",
        record_id="rec",
        rf_model_version="network_random_forest_baseline_v1",
        rf_attack_probability=0.5,
        rf_threshold=0.5,
        top_feature_signals={},
    )
    prompt = build_grounded_gemini_prompt(bundle)
    assert SOC_COPILOT_SYSTEM_PROMPT in prompt
    assert "NO IP ADDRESS HALLUCINATIONS" in prompt
    assert "fusion is disabled" in prompt or "fusion_disabled" in prompt


def test_missing_key_and_budget_ceiling_do_not_call_the_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)
    status = advisory_provider_status()
    assert status["provider"] == "local_air_gapped"
    assert status["label"] == "AI Copilot: Local Air-Gapped Engine"
    with pytest.raises(GeminiAdvisoryUnavailableError):
        GeminiAdvisoryCallable().generate_copilot_text("Stored decision Benign.")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-used")
    monkeypatch.setenv("THREATFUSION_CLOUD_SPEND_USD", "5.00")
    blocked = advisory_provider_status()
    assert blocked["live_call_allowed"] is False
    with pytest.raises(GeminiAdvisoryUnavailableError):
        GeminiAdvisoryCallable().generate_copilot_text("Stored decision Benign.")


def test_groundedness_refuses_an_address_absent_from_the_evidence() -> None:
    bundle = AdvisoryEvidenceBundle(
        candidate_id="cand",
        record_id="rec",
        rf_model_version="network_random_forest_baseline_v1",
        rf_attack_probability=0.2,
        rf_threshold=0.5,
        top_feature_signals={},
    )
    assert verify_explanation_groundedness("host 198.51.100.99 was isolated", bundle) is False
    assert verify_explanation_groundedness("The stored decision is Benign.", bundle) is True


def test_copilot_without_a_key_returns_the_local_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)
    answer = answer_mitre_copilot("ssh brute force", tmp_path / "rag.sqlite3")
    assert answer["provider"] == "local_air_gapped"
    assert answer["narrative"] == ""
    assert answer["execution_authorized"] is False
    assert answer["reason"] in {"local_corpus", "no_corpus_hit"}
