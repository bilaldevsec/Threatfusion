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


def test_unset_model_stays_gemini_3_5_flash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert GeminiAdvisoryConfig().model_name == "gemini-3.5-flash"
    assert resolve_gemini_model() == "gemini-3.5-flash"
    dashboard = Path(__file__).resolve().parents[3] / "frontend" / "js" / "soc_dashboard.js"
    assert "Live Gemini 3.5 Flash (Grounded API Call)" in dashboard.read_text(encoding="utf-8")
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


def test_copilot_retries_503_and_timeout_across_fallback_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io
    import urllib.error

    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)
    seen: list[str] = []

    def transport(endpoint_url: str, payload: dict) -> dict:
        del payload
        seen.append(endpoint_url)
        if endpoint_url.endswith("models/gemini-3.5-flash:generateContent"):
            raise urllib.error.HTTPError(
                endpoint_url, 503, "unavailable", hdrs=None, fp=io.BytesIO(b"{}")
            )
        if endpoint_url.endswith("models/gemini-3.6-flash:generateContent"):
            raise TimeoutError("timed out")
        if endpoint_url.endswith("models/gemini-3.7-flash:generateContent"):
            return {"candidates": [{"content": {"parts": [{"text": "live brief"}]}}]}
        raise AssertionError(endpoint_url)

    text = GeminiAdvisoryCallable(transport_callable=transport).generate_copilot_text("evidence")
    assert text == "live brief"
    assert [url.rsplit("/", 1)[-1] for url in seen] == [
        "gemini-3.5-flash:generateContent",
        "gemini-3.6-flash:generateContent",
        "gemini-3.7-flash:generateContent",
    ]
    assert all("key=" not in url for url in seen)


def test_copilot_does_not_hop_models_on_http_401(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import urllib.error

    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen: list[str] = []

    def transport(endpoint_url: str, payload: dict) -> dict:
        del payload
        seen.append(endpoint_url)
        raise urllib.error.HTTPError(endpoint_url, 401, "denied", hdrs=None, fp=io.BytesIO(b""))

    with pytest.raises(GeminiAdvisoryUnavailableError):
        GeminiAdvisoryCallable(transport_callable=transport).generate_copilot_text("evidence")
    assert len(seen) == 1


def test_copilot_raises_after_every_fallback_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen: list[str] = []

    def transport(endpoint_url: str, payload: dict) -> dict:
        del payload
        seen.append(endpoint_url)
        raise TimeoutError("timed out")

    with pytest.raises(GeminiAdvisoryUnavailableError):
        GeminiAdvisoryCallable(transport_callable=transport).generate_copilot_text("evidence")
    assert len(seen) == 5


def test_missing_heading_is_kept_and_foreign_ids_are_still_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from threatfusion.api import live_soc_console as console

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)

    class _Client:
        def __init__(self, text: str) -> None:
            self._text = text

        def generate_copilot_text(self, evidence_text: str) -> str:
            return self._text

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client("The stored decision is Benign. No new address is named."),
    )
    kept = console._grounded_gemini_narrative(
        "review",
        [],
        evidence_text="Stored decision Benign.",
        local_narrative="local brief",
    )
    assert kept["provider"] == "gemini"
    assert "The stored decision is Benign." in kept["narrative"]
    for heading in console._COPILOT_HEADINGS:
        assert heading in kept["narrative"]

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client("Indexed technique T1071.001 applies to the stored flow."),
    )
    indexed = console._grounded_gemini_narrative(
        "review",
        [],
        evidence_text="Stored decision Benign.",
        local_narrative="local brief",
    )
    assert indexed["provider"] == "gemini"
    assert "T1071.001" in indexed["narrative"]

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client("Contact 198.51.100.99 and 203.0.113.99 about this row."),
    )
    foreign = console._grounded_gemini_narrative(
        "review",
        [],
        evidence_text="Stored source only.",
        local_narrative="local brief",
    )
    assert foreign["provider"] == "local_air_gapped"
    assert foreign["narrative"] == "local brief"

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client("[1] EXECUTIVE TRIAGE & MODEL AUTHORITY\nTechnique T9999."),
    )
    invented = console._grounded_gemini_narrative(
        "review",
        [],
        evidence_text="Stored decision Benign.",
        local_narrative="local brief",
    )
    assert invented["provider"] == "local_air_gapped"
    assert invented["narrative"] == "local brief"


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
