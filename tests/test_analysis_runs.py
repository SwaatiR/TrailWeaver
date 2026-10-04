from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from trailweaver.analysis_runs import AnalysisRun, AnalysisSourceType

STARTED_AT = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
COMPLETED_AT = STARTED_AT + timedelta(seconds=1)


def _analysis_run(**overrides: object) -> AnalysisRun:
    values: dict[str, object] = {
        "source_type": AnalysisSourceType.LOCAL_FILE,
        "source_label": "export.json",
        "started_at": STARTED_AT,
        "completed_at": COMPLETED_AT,
        "records_seen": 5,
        "records_accepted": 4,
        "signals_created": 3,
        "correlations_created": 1,
        "incidents_created": 1,
    }
    values.update(overrides)
    return AnalysisRun(**values)  # type: ignore[arg-type]


def test_generated_analysis_run_ids_are_distinct_uuid4_values() -> None:
    first = _analysis_run()
    second = _analysis_run()

    assert UUID(first.analysis_run_id).version == 4
    assert UUID(second.analysis_run_id).version == 4
    assert first.analysis_run_id != second.analysis_run_id


def test_explicit_analysis_run_id_is_preserved() -> None:
    run = _analysis_run(analysis_run_id="analysis-run-imported-123")

    assert run.analysis_run_id == "analysis-run-imported-123"


def test_analysis_run_is_immutable() -> None:
    run = _analysis_run()

    with pytest.raises(FrozenInstanceError):
        run.records_seen = 9  # type: ignore[misc]


def test_analysis_source_type_values_are_stable() -> None:
    assert {source_type.value for source_type in AnalysisSourceType} == {
        "local_file",
        "web_upload",
        "s3_object",
        "direct_input",
    }


def test_timezone_aware_timestamps_are_accepted() -> None:
    run = _analysis_run()

    assert run.started_at is STARTED_AT
    assert run.completed_at is COMPLETED_AT


@pytest.mark.parametrize("field_name", ("started_at", "completed_at"))
def test_naive_timestamps_are_rejected(field_name: str) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _analysis_run(
            **{field_name: datetime(2026, 10, 4, 10, 0)}  # noqa: DTZ001
        )


def test_completion_before_start_is_rejected() -> None:
    with pytest.raises(ValueError, match="before started_at"):
        _analysis_run(completed_at=STARTED_AT - timedelta(microseconds=1))


@pytest.mark.parametrize(
    "field_name",
    (
        "records_seen",
        "records_accepted",
        "signals_created",
        "correlations_created",
        "incidents_created",
    ),
)
def test_negative_counts_are_rejected(field_name: str) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        _analysis_run(**{field_name: -1})


def test_accepted_records_cannot_exceed_seen_records() -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        _analysis_run(records_seen=1, records_accepted=2)


@pytest.mark.parametrize(
    "overrides, message",
    (
        ({"analysis_run_id": ""}, "analysis_run_id"),
        ({"analysis_run_id": "   "}, "analysis_run_id"),
        ({"source_label": ""}, "source_label"),
        ({"source_label": "   "}, "source_label"),
    ),
)
def test_empty_identity_and_labels_are_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _analysis_run(**overrides)


def test_null_source_label_is_accepted() -> None:
    assert _analysis_run(source_label=None).source_label is None
