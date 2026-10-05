"""Cold-start recovery for exclusively owned persistent SQLite databases.

When a new TrailWeaver process starts and inherits ``RUNNING`` analysis rows
from the previous ownership epoch, those unfinished lifecycles are classified
as INTERRUPTED before the new owner accepts or starts analyses.

INTERRUPTED does not prove a crash. It means a new exclusive database owner
inherited the run in a nonterminal state and classified it as interrupted;
the exact interruption point is unknown, and the classification timestamp is
not the interruption time. Recovery never replays, resumes, or reconstructs
anything: no events, no signal history, no output counts, no failure phase.
"""

import logging
from datetime import UTC, datetime

from trailweaver.analysis_ledger import (
    AnalysisRunRecoveryRepository,
    AnalysisRunRepositoryError,
    InvalidAnalysisRunTransitionError,
)
from trailweaver.observability import log_event

_LOGGER = logging.getLogger(__name__)


class AnalysisRunRecoveryError(AnalysisRunRepositoryError):
    """Raised when persistent startup recovery cannot complete safely."""


def recover_interrupted_runs(
    repository: AnalysisRunRecoveryRepository,
    *,
    interrupted_at: datetime | None = None,
) -> int:
    """Classify inherited RUNNING runs as INTERRUPTED and return the count.

    Captures one UTC-aware classification timestamp shared by every
    transitioned row. Any repository failure aborts startup: callers must
    not serve analyses or begin new work when this raises.
    """

    stamp = interrupted_at if interrupted_at is not None else datetime.now(UTC)
    try:
        transitioned = repository.mark_running_runs_interrupted(interrupted_at=stamp)
    except (AnalysisRunRepositoryError, InvalidAnalysisRunTransitionError) as error:
        log_event(
            _LOGGER,
            logging.ERROR,
            "analysis_run_recovery_failed",
            error_type=type(error).__name__,
        )
        raise AnalysisRunRecoveryError(
            "Analysis run recovery did not complete"
        ) from error
    log_event(
        _LOGGER,
        logging.INFO,
        "analysis_run_recovery_completed",
        interrupted_runs=transitioned,
    )
    return transitioned
