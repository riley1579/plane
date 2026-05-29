# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import logging
from typing import Any, Dict

# Third party imports
from celery import shared_task

# Module imports
from plane.db.models import AuthenticationAuditLog
from plane.utils.exception_logger import log_exception

logger = logging.getLogger("plane.worker")


@shared_task
def record_auth_event(log_data: Dict[str, Any], **_: Any) -> None:
    """
    Persist an authentication audit event to PostgreSQL.

    Runs off the request path so auditing never adds latency to login/logout.
    Failures are logged but swallowed: an audit-write error must not break the
    user's authentication flow.
    """
    try:
        AuthenticationAuditLog.objects.create(**log_data)
    except Exception as e:
        log_exception(e)
