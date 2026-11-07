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
    monkeypatch.delenv("GEMINI_ENABLED", raising=False)
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)
    status = advisory_provider_status()
    assert status["provider"] == "local_air_gapped"
    assert status["label"] == "AI Copilot: Local Air-Gapped Engine"
    with pytest.raises(GeminiAdvisoryUnavailableError):
        GeminiAdvisoryCallable().generate_copilot_text("Stored decision Benign.")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-used")
    still_off = advisory_provider_status()
    assert still_off["provider"] == "local_air_gapped"
    assert still_off["live_call_allowed"] is False
    monkeypatch.setenv("GEMINI_ENABLED", "true")
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
    monkeypatch.setenv("GEMINI_ENABLED", "true")
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)
    seen: list[str] = []

    def transport(endpoint_url: str, payload: dict) -> dict:
        del payload
        seen.append(endpoint_url)
        if endpoint_url.endswith("models/gemini-3.5-flash:generateContent"):
            raise urllib.error.HTTPError(
                endpoint_url, 404, "not found", hdrs=None, fp=io.BytesIO(b"{}")
            )
        if endpoint_url.endswith("models/gemini-3.5-flash-lite:generateContent"):
            raise urllib.error.HTTPError(
                endpoint_url, 503, "unavailable", hdrs=None, fp=io.BytesIO(b"{}")
            )
        if endpoint_url.endswith("models/gemini-3.1-flash-lite:generateContent"):
            return {"candidates": [{"content": {"parts": [{"text": "live brief"}]}}]}
        raise AssertionError(endpoint_url)

    text = GeminiAdvisoryCallable(transport_callable=transport).generate_copilot_text("evidence")
    assert text == "live brief"
    assert [url.rsplit("/", 1)[-1] for url in seen] == [
        "gemini-3.5-flash:generateContent",
        "gemini-3.5-flash-lite:generateContent",
        "gemini-3.1-flash-lite:generateContent",
    ]
    assert all("key=" not in url for url in seen)


def test_copilot_does_not_hop_models_on_http_401(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import urllib.error

    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_ENABLED", "true")
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
    monkeypatch.setenv("GEMINI_ENABLED", "true")
    seen: list[str] = []

    def transport(endpoint_url: str, payload: dict) -> dict:
        del payload
        seen.append(endpoint_url)
        raise TimeoutError("timed out")

    with pytest.raises(GeminiAdvisoryUnavailableError):
        GeminiAdvisoryCallable(transport_callable=transport).generate_copilot_text("evidence")
    assert len(seen) == 5


def _five_section_reply(*sentences: str) -> str:
    from threatfusion.api import live_soc_console as console

    body = " ".join(sentences) if sentences else "The stored decision is Benign."
    sentence = body if body.endswith(".") else body + "."
    if len(sentence) < 40:
        sentence = sentence + " This sentence stays on the stored flow."
    return "\n\n".join(f"{heading}\n{sentence}" for heading in console._COPILOT_HEADINGS)


def test_missing_heading_is_kept_and_foreign_ids_are_still_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from threatfusion.api import live_soc_console as console

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_ENABLED", "true")
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
    assert kept["provider"] == "local_air_gapped"
    assert kept["narrative"] == "local brief"

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client(
            _five_section_reply("Indexed technique T1071.001 applies to the stored flow")
        ),
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


def test_attack_rows_keep_live_text_after_unindexed_ids_are_rewritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from threatfusion.api import live_soc_console as console

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_ENABLED", "true")
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)
    console._LIVE_GEMINI_CACHE.clear()

    class _Client:
        def __init__(self, text: str) -> None:
            self.calls = 0
            self._text = text

        def generate_copilot_text(self, evidence_text: str) -> str:
            del evidence_text
            self.calls += 1
            return self._text

    client = _Client(
        _five_section_reply(
            "Related sub-technique T1498.001 and external CVE-2099-1111 expand indexed T1498"
        )
    )
    monkeypatch.setattr(console, "_live_copilot_callable", lambda: client)
    hits = [
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "playbook_id": "pb-dos",
            "doc_id": "mitre-t1498",
        }
    ]
    kept = console._grounded_gemini_narrative(
        "Review this attack",
        hits,
        evidence_text="Stored decision Attack. Technique T1498.",
        local_narrative="local brief",
        flow_hits=hits,
        decision="Attack",
        source_label="recorded_unsw_nb15",
        flow_id=7,
    )
    assert kept["provider"] == "gemini"
    assert "T1498.001" not in kept["narrative"]
    assert "CVE-2099-1111" not in kept["narrative"]
    assert "T1498" in kept["narrative"]
    again = console._grounded_gemini_narrative(
        "  review this attack  ",
        hits,
        evidence_text="Stored decision Attack. Technique T1498.",
        local_narrative="local brief",
        flow_hits=hits,
        decision="Attack",
        source_label="recorded_unsw_nb15",
        flow_id=7,
    )
    assert again["narrative"] == kept["narrative"]
    assert client.calls == 1
    console._LIVE_GEMINI_CACHE.clear()


def test_anonymized_study_rows_strip_example_ips_and_keep_poison_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from threatfusion.api import live_soc_console as console

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_ENABLED", "true")
    monkeypatch.delenv("THREATFUSION_CLOUD_SPEND_USD", raising=False)

    class _Client:
        def __init__(self, text: str) -> None:
            self._text = text

        def generate_copilot_text(self, evidence_text: str) -> str:
            del evidence_text
            return self._text

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client(
            _five_section_reply(
                "Example address 8.8.8.8 is not stored on this anonymized study row"
            )
        ),
    )
    kept = console._grounded_gemini_narrative(
        "review study",
        [],
        evidence_text="Stored decision Benign.",
        local_narrative="local brief",
        source_label="recorded_unsw_nb15",
    )
    assert kept["provider"] == "gemini"
    assert "8.8.8.8" not in kept["narrative"]
    assert "anonymized study row" in kept["narrative"]

    monkeypatch.setattr(
        console,
        "_live_copilot_callable",
        lambda: _Client(
            _five_section_reply("Contact 198.51.100.99 and 203.0.113.99 about this study row")
        ),
    )
    blocked = console._grounded_gemini_narrative(
        "review poison",
        [],
        evidence_text="Stored decision Benign.",
        local_narrative="local brief",
        source_label="recorded_unsw_nb15",
    )
    assert blocked["provider"] == "local_air_gapped"
    assert blocked["narrative"] == "local brief"


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
