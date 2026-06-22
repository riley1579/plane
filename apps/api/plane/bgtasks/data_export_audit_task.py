# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import logging
from typing import Any, Dict

# Third party imports
from celery import shared_task

# Module imports
from plane.db.models import DataExportAuditLog
from plane.utils.exception_logger import log_exception

logger = logging.getLogger("plane.worker")


@shared_task
def record_data_export_event(log_data: Dict[str, Any], **_: Any) -> None:
    """
    Persist a bulk data-export audit event to PostgreSQL.

    Runs off the request path so auditing never adds latency to export requests.
    Failures are logged but swallowed: an audit-write error must not break the
    export it is observing.
    """
    try:
        # The actor (created_by) is captured in the request and passed through as
        # actor_id. crum.get_current_user() is empty inside the worker, so build
        # the row explicitly and bypass BaseModel's auto-set (which would null it).
        actor_id = log_data.pop("actor_id", None)
        log = DataExportAuditLog(created_by_id=actor_id, **log_data)
        log.save(disable_auto_set_user=True)
    except Exception as e:
        log_exception(e)
