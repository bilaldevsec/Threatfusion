import pytest

from threatfusion.datasets.split_policy import (
    PHASE0_SPLIT_POLICY,
    DatasetSplitRule,
    DatasetUse,
    LeakageSafeSplitPolicy,
    SplitAssignment,
    SplitName,
)


def test_ungrouped_random_split_is_rejected() -> None:
    with pytest.raises(ValueError, match="ungrouped random"):
        LeakageSafeSplitPolicy(rules=(), allow_ungrouped_random=True)


def test_valid_source_group_and_time_aware_policy_is_accepted() -> None:
    policy = LeakageSafeSplitPolicy(
        rules=(
            DatasetSplitRule(
                source_dataset="unsw_nb15",
                use=DatasetUse.TRAINING_DEVELOPMENT,
                group_by="source_file_or_capture_session",
                timestamps_reliable=True,
                time_aware=True,
            ),
            DatasetSplitRule(
                source_dataset="cse_cic_ids2018",
                use=DatasetUse.EXTERNAL_EVALUATION,
                group_by="source_file",
                timestamps_reliable=False,
                time_aware=False,
            ),
        )
    )

    policy.validate_assignments(
        (
            SplitAssignment("unsw_nb15", "capture-a", SplitName.TRAIN),
            SplitAssignment("unsw_nb15", "capture-b", SplitName.VALIDATION),
            SplitAssignment("cse_cic_ids2018", "external-a", SplitName.EXTERNAL_TEST),
        )
    )


def test_same_source_group_cannot_cross_splits() -> None:
    assignments = (
        SplitAssignment("unsw_nb15", "capture-a", SplitName.TRAIN),
        SplitAssignment("unsw_nb15", "capture-a", SplitName.TEST),
    )

    with pytest.raises(ValueError, match="cannot appear in multiple splits"):
        PHASE0_SPLIT_POLICY.validate_assignments(assignments)


@pytest.mark.parametrize(
    ("source_dataset", "split"),
    [
        ("cse_cic_ids2018", SplitName.TRAIN),
        ("cse_cic_ids2018", SplitName.VALIDATION),
        ("cse_cic_ids2018", SplitName.TEST),
        ("mordor", SplitName.TRAIN),
        ("mordor", SplitName.VALIDATION),
        ("synthetic_lab", SplitName.TRAIN),
        ("synthetic_lab", SplitName.VALIDATION),
        ("synthetic_lab", SplitName.TEST),
        ("synthetic_lab", SplitName.EXTERNAL_TEST),
    ],
)
def test_source_policy_rejects_unsupported_assignments(
    source_dataset: str, split: SplitName
) -> None:
    with pytest.raises(ValueError, match="does not allow split"):
        PHASE0_SPLIT_POLICY.validate_assignments(
            (SplitAssignment(source_dataset, "fixture-group", split),)
        )


def test_external_and_pipeline_assignments_are_allowed() -> None:
    PHASE0_SPLIT_POLICY.validate_assignments(
        (
            SplitAssignment("cse_cic_ids2018", "capture", SplitName.EXTERNAL_TEST),
            SplitAssignment("mordor", "scenario", SplitName.EXTERNAL_TEST),
            SplitAssignment("synthetic_lab", "session", SplitName.PIPELINE_TEST),
        )
    )


def test_unknown_source_assignment_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown source dataset"):
        PHASE0_SPLIT_POLICY.validate_assignments(
            (SplitAssignment("unknown_source", "group", SplitName.TRAIN),)
        )


def test_synthetic_fixture_cannot_be_configured_for_training() -> None:
    with pytest.raises(ValueError, match="restricted to pipeline fixture"):
        DatasetSplitRule(
            source_dataset="synthetic_lab",
            use=DatasetUse.TRAINING_DEVELOPMENT,
            group_by="source_file_session",
            timestamps_reliable=True,
            time_aware=True,
        )


@pytest.mark.parametrize("source_dataset", ["cse_cic_ids2018", "mordor"])
def test_external_sources_require_explicit_training_approval(source_dataset: str) -> None:
    with pytest.raises(ValueError, match="default to external evaluation"):
        DatasetSplitRule(
            source_dataset=source_dataset,
            use=DatasetUse.TRAINING_DEVELOPMENT,
            group_by="source_file",
            timestamps_reliable=False,
            time_aware=False,
        )


def test_reliable_timestamps_require_time_aware_splitting() -> None:
    with pytest.raises(ValueError, match="time-aware"):
        DatasetSplitRule(
            source_dataset="unsw_nb15",
            use=DatasetUse.TRAINING_DEVELOPMENT,
            group_by="source_file",
            timestamps_reliable=True,
            time_aware=False,
        )
