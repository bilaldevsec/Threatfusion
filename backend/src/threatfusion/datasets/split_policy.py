"""Typed source-, group-, and time-aware dataset split policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DatasetUse(str, Enum):
    """Permitted high-level use of a registered source."""

    TRAINING_DEVELOPMENT = "training_development"
    EXTERNAL_EVALUATION = "external_evaluation"
    PIPELINE_FIXTURE = "pipeline_fixture"


class SplitName(str, Enum):
    """Named partitions accepted by group-overlap validation."""

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    EXTERNAL_TEST = "external_test"
    PIPELINE_TEST = "pipeline_test"


@dataclass(frozen=True, slots=True)
class DatasetSplitRule:
    """One dataset's role and reliable split dimensions."""

    source_dataset: str
    use: DatasetUse
    group_by: str
    timestamps_reliable: bool
    time_aware: bool
    explicitly_approved_for_training: bool = False

    def __post_init__(self) -> None:
        if not self.source_dataset.strip() or not self.group_by.strip():
            raise ValueError("source_dataset and group_by must be nonblank")
        if self.timestamps_reliable and not self.time_aware:
            raise ValueError("reliable timestamps require a time-aware split")
        if (
            self.source_dataset in {"cse_cic_ids2018", "mordor"}
            and self.use is DatasetUse.TRAINING_DEVELOPMENT
            and not self.explicitly_approved_for_training
        ):
            raise ValueError("CIC and Mordor default to external evaluation")
        if self.source_dataset == "synthetic_lab" and self.use is not DatasetUse.PIPELINE_FIXTURE:
            raise ValueError("synthetic_lab is restricted to pipeline fixture use")


@dataclass(frozen=True, slots=True)
class SplitAssignment:
    """Safe split identity for checking source-group overlap."""

    source_dataset: str
    source_group: str
    split: SplitName


@dataclass(frozen=True, slots=True)
class LeakageSafeSplitPolicy:
    """Policy invariants required before constructing any row assignments."""

    rules: tuple[DatasetSplitRule, ...]
    source_aware: bool = True
    group_aware: bool = True
    allow_ungrouped_random: bool = False
    enforce_group_exclusivity: bool = True

    def __post_init__(self) -> None:
        if not self.source_aware:
            raise ValueError("split policy must be source-aware")
        if not self.group_aware:
            raise ValueError("split policy must be group-aware")
        if self.allow_ungrouped_random:
            raise ValueError("ungrouped random row splits are prohibited")
        if not self.enforce_group_exclusivity:
            raise ValueError("source groups must be exclusive to one split")
        sources = [rule.source_dataset for rule in self.rules]
        if len(sources) != len(set(sources)):
            raise ValueError("each source dataset must have exactly one split rule")

    def validate_assignments(self, assignments: tuple[SplitAssignment, ...]) -> None:
        """Reject unknown sources, unsupported roles, and cross-partition groups."""
        rules_by_source = {rule.source_dataset: rule for rule in self.rules}
        assigned: dict[tuple[str, str], SplitName] = {}
        for assignment in assignments:
            if not assignment.source_dataset.strip():
                raise ValueError("assignment source_dataset must be nonblank")
            if not assignment.source_group.strip():
                raise ValueError("assignment source_group must be nonblank")
            rule = rules_by_source.get(assignment.source_dataset)
            if rule is None:
                raise ValueError(f"unknown source dataset: {assignment.source_dataset}")
            allowed_splits = {
                DatasetUse.TRAINING_DEVELOPMENT: frozenset(
                    {SplitName.TRAIN, SplitName.VALIDATION, SplitName.TEST}
                ),
                DatasetUse.EXTERNAL_EVALUATION: frozenset({SplitName.EXTERNAL_TEST}),
                DatasetUse.PIPELINE_FIXTURE: frozenset({SplitName.PIPELINE_TEST}),
            }[rule.use]
            if assignment.split not in allowed_splits:
                raise ValueError(
                    f"source dataset {assignment.source_dataset} does not allow "
                    f"split {assignment.split.value}"
                )
            key = (assignment.source_dataset, assignment.source_group)
            previous = assigned.setdefault(key, assignment.split)
            if previous != assignment.split:
                raise ValueError("a source group cannot appear in multiple splits")


PHASE0_SPLIT_POLICY = LeakageSafeSplitPolicy(
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
        DatasetSplitRule(
            source_dataset="mordor",
            use=DatasetUse.EXTERNAL_EVALUATION,
            group_by="source_file_or_scenario_session",
            timestamps_reliable=True,
            time_aware=True,
        ),
        DatasetSplitRule(
            source_dataset="synthetic_lab",
            use=DatasetUse.PIPELINE_FIXTURE,
            group_by="source_file_session",
            timestamps_reliable=True,
            time_aware=True,
        ),
    )
)
