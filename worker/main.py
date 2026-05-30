from __future__ import annotations

import argparse
import logging
import time

from api.core.config import get_settings
from api.core.logging import configure_logging
from api.db.init_db import init_db
from worker.jobs.cleanup_expired_challenges import cleanup_expired_challenges
from worker.jobs.cleanup_orphan_objects import cleanup_orphan_objects
from worker.jobs.reconcile_pending_uploads import reconcile_pending_uploads

logger = logging.getLogger(__name__)


def run_once() -> None:
    challenge_count = cleanup_expired_challenges()
    upload_count = reconcile_pending_uploads()
    orphan_count = cleanup_orphan_objects()
    logger.info(
        "worker pass finished: expired_challenges=%s expired_uploads=%s orphan_files=%s",
        challenge_count,
        upload_count,
        orphan_count,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure dedup background worker")
    parser.add_argument("--once", action="store_true", help="Run one cleanup pass and exit")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=60,
        help="Loop interval when not using --once",
    )
    return parser


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()

    parser = build_parser()
    args = parser.parse_args()

    if args.once:
        run_once()
        return 0

    logger.info("worker started in loop mode; interval=%s seconds", args.interval_seconds)
    while True:
        try:
            run_once()
        except Exception:  # pragma: no cover - defensive runtime logging
            logger.exception("worker iteration failed")
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
