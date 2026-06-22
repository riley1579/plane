# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Helpers for recording data-export audit events.

Thin wrapper around the async ``record_data_export_event`` task so call sites in
the export views stay one-liners and never block the request path.
"""

# Module imports
from plane.bgtasks.data_export_audit_task import record_data_export_event
from plane.utils.exception_logger import log_exception
from plane.utils.ip_address import get_client_ip


def record_export_event(
    request,
    export_type,
    workspace_id=None,
    provider=None,
    project_count=None,
):
    """Enqueue a data-export audit event.

    The requesting user is taken from ``request.user`` and stored as
    ``created_by``. Best-effort: any failure to capture/enqueue is logged and
    swallowed so it can never break the export flow it is observing.
    """
    try:
        actor = getattr(request, "user", None)
        log_data = {
            "export_type": export_type,
            "provider": provider,
            "workspace_id": workspace_id,
            "project_count": project_count,
            "actor_id": getattr(actor, "id", None) if actor and getattr(actor, "is_authenticated", False) else None,
            "ip_address": get_client_ip(request=request),
            "user_agent": (request.META.get("HTTP_USER_AGENT", "") or "")[:512],
        }
        record_data_export_event.delay(log_data=log_data)
    except Exception as e:
        log_exception(e)
