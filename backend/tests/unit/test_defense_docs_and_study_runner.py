"""Unit tests for Section 13.F study runner and harmonized defense documentation generator."""

from __future__ import annotations

from pathlib import Path
import xml.sax.saxutils as saxutils
import zipfile

from scripts.generate_harmonized_defense_docs import (
    generate_harmonized_defense_docs,
)
from threatfusion.evaluation.study_runner import (
    STUDY_TRIAGE_CASES,
    run_automated_smoke_study,
    run_interactive_study,
)
from threatfusion.evaluation.workload_measurement import (
    AnalystWorkloadStudyRepository,
)

UNROUNDED_REV2_METRICS = (
    "0.1181361214680695",
    "212,009",
    "313",
    "95.266%",
    "92.818%",
    "94.026%",
    "8.8308x",
    "16.3958",
)

SPEAKERS = (
    "21K-3551",
    "22K-4302",
    "22K-4718",
)

SLIDE_14_QUALIFIED_BADGE = (
    "BOUNDED RECORDED/LOCAL INTEGRATION PATH VERIFIED (16/16 TEST GATES); "
    "LIVE AZURE/SIEM DEPLOYMENT OPEN (TF-011)"
)

SLIDE_14_QUALIFIED_FOOTER = (
    "Repository software spine (Suricata eve.json -> 14 features -> loopback mTLS 1.3 -> "
    "Frozen RF -> Correlation -> RFC1918 Threat-Intel -> Advisory -> Reversible SOAR) is "
    "verified by automated integration tests (test_slide14_suricata_live_ingestion_path.py); "
    "live Azure VM / production SIEM field deployment remains unverified and open under TF-011."
)


def test_automated_smoke_study_runner(tmp_path: Path) -> None:
    """Verify run_automated_smoke_study executes 20 trials and enforces tf_009_closure_eligible is False."""
    db_path = tmp_path / "smoke_workload_study.sqlite3"
    summary = run_automated_smoke_study(db_path=db_path)

    assert summary.study_cohort == "synthetic_smoke_verification"
    assert summary.total_trials == 20
    assert summary.baseline_trials == 10
    assert summary.threatfusion_trials == 10
    assert summary.tf_009_closure_eligible is False
    assert "Synthetic cohort cannot satisfy TF-009" in summary.notes
    assert (
        summary.baseline_mean_time_to_disposition_ms
        > summary.threatfusion_mean_time_to_disposition_ms
    )
    assert summary.speedup_pct > 0.0
    assert summary.threatfusion_accuracy_pct >= summary.baseline_accuracy_pct

    # Verify database contents
    repo = AnalystWorkloadStudyRepository(db_path)
    trials = repo.list_trials(study_cohort="synthetic_smoke_verification")
    assert len(trials) == 20
    assert all(t.study_cohort == "synthetic_smoke_verification" for t in trials)


def test_interactive_study_runner_scripted(tmp_path: Path) -> None:
    """Verify interactive study runner with scripted input_fn records human_analyst_cohort_study trials accurately."""
    db_path = tmp_path / "human_workload_study.sqlite3"
    reports_dir = tmp_path / "study_reports"

    # Scripted input: 10 baseline choices followed by 10 threatfusion choices
    # Provide 'e' for attack, 'd' for benign
    scripted_responses = [
        "e",
        "e",
        "d",
        "d",
        "e",
        "e",
        "r",
        "d",
        "e",
        "d",  # Condition A
        "e",
        "e",
        "d",
        "d",
        "e",
        "e",
        "r",
        "d",
        "e",
        "d",  # Condition B
    ]
    response_idx = 0

    def mock_input(_prompt: str) -> str:
        nonlocal response_idx
        res = scripted_responses[response_idx % len(scripted_responses)]
        response_idx += 1
        return res

    summary, json_path, md_path = run_interactive_study(
        db_path=db_path,
        participant_id="21K-3551",
        output_dir=reports_dir,
        input_fn=mock_input,
    )

    assert summary.study_cohort == "human_analyst_cohort_study"
    assert summary.total_trials == 20
    assert summary.baseline_trials == 10
    assert summary.threatfusion_trials == 10
    assert summary.tf_009_closure_eligible is True  # Satisfies human study with >=10 trials

    # Verify generated report files
    assert json_path.exists()
    assert md_path.exists()
    assert json_path.stat().st_size > 0
    assert md_path.stat().st_size > 0

    md_content = md_path.read_text(encoding="utf-8")
    assert "21K-3551" in md_content
    assert "human_analyst_cohort_study" in md_content
    assert "TF-009 Closure Eligible" in md_content


def test_generate_harmonized_defense_docs(tmp_path: Path) -> None:
    """Verify generate_harmonized_defense_docs creates valid .docx and .md files with exact Rev2 content."""
    out_dir = tmp_path / "reports"
    guide_md_path = tmp_path / "guide.md"

    md_file, guide_docx_path, report_docx_path = generate_harmonized_defense_docs(
        output_dir=out_dir,
        markdown_path=guide_md_path,
    )

    assert md_file == guide_md_path
    assert md_file.exists()
    assert guide_docx_path.exists()
    assert report_docx_path.exists()

    md_text = md_file.read_text(encoding="utf-8")
    with zipfile.ZipFile(guide_docx_path) as zf:
        guide_xml = saxutils.unescape(zf.read("word/document.xml").decode("utf-8"))
    with zipfile.ZipFile(report_docx_path) as zf:
        report_xml = saxutils.unescape(zf.read("word/document.xml").decode("utf-8"))

    documents = (
        ("Presenter Guide Markdown", md_text),
        ("Presenter Guide DOCX", guide_xml),
        ("Final Report DOCX", report_xml),
    )

    for doc_name, text in documents:
        # 1. Assert all 8 unrounded metrics
        for metric in UNROUNDED_REV2_METRICS:
            assert metric in text, f"{doc_name} missing unrounded Rev2 metric: {metric}"

        # 2. Assert all 3 speaker roll numbers
        for roll_no in SPEAKERS:
            assert roll_no in text, f"{doc_name} missing speaker roll number: {roll_no}"

        # 3. Assert qualified Slide 14 badge and footer
        assert SLIDE_14_QUALIFIED_BADGE in text, f"{doc_name} missing qualified Slide 14 badge"
        assert SLIDE_14_QUALIFIED_FOOTER in text, f"{doc_name} missing qualified Slide 14 footer"

        # 4. Assert zero unqualified claims
        assert (
            "VERIFIED & OPERATIONAL" not in text
        ), f"{doc_name} contains unqualified 'VERIFIED & OPERATIONAL'"
        assert "100% operational" not in text, f"{doc_name} contains unqualified '100% operational'"

        # 5. Assert open issues disclosed honestly
        for issue_id in ("TF-008", "TF-009", "TF-010", "TF-011"):
            assert issue_id in text, f"{doc_name} missing open issue disclosure: {issue_id}"


def test_study_triage_cases_structure() -> None:
    """Verify structure and distribution of STUDY_TRIAGE_CASES."""
    assert len(STUDY_TRIAGE_CASES) == 10
    attack_cases = [c for c in STUDY_TRIAGE_CASES if c.expected_disposition == "escalated"]
    benign_cases = [
        c for c in STUDY_TRIAGE_CASES if c.expected_disposition in ("dismissed", "resolved")
    ]
    assert len(attack_cases) == 5
    assert len(benign_cases) == 5

    unsw_cases = [c for c in STUDY_TRIAGE_CASES if c.source == "recorded_unsw_nb15"]
    suricata_cases = [c for c in STUDY_TRIAGE_CASES if c.source == "slide14_azure_suricata_eve"]
    assert len(unsw_cases) == 5
    assert len(suricata_cases) == 5

    for case in STUDY_TRIAGE_CASES:
        assert len(case.raw_features_14) == 14
        assert case.baseline_view["condition"] == "baseline_raw_alert_only"
        assert case.threatfusion_view["condition"] == "threatfusion_enriched_advisory_soar"
        assert "rf_precision_context" in case.threatfusion_view
        assert "section_8_fusion_policy" in case.threatfusion_view
