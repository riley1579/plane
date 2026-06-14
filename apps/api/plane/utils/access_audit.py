# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Helpers for recording access-management audit events.

Thin wrapper around the async ``record_access_event`` task so call sites in the
member/role views stay one-liners and never block the request path.
"""

# Module imports
from plane.bgtasks.access_audit_task import record_access_event
from plane.utils.exception_logger import log_exception
from plane.utils.ip_address import get_client_ip


def record_access_management_event(
    request,
    event_type,
    scope,
    workspace_id=None,
    project_id=None,
    target_user=None,
    target_email=None,
    previous_role=None,
    new_role=None,
):
    """Enqueue an access-management audit event.

    The acting user (who performed the change) is taken from ``request.user``
    and stored as ``created_by``. Best-effort: any failure to capture/enqueue is
    logged and swallowed so it can never break the access-management flow it is
    observing.
    """
    try:
        actor = getattr(request, "user", None)
        log_data = {
            "event_type": event_type,
            "scope": scope,
            "workspace_id": workspace_id,
            "project_id": project_id,
            "target_user_id": getattr(target_user, "id", None),
            "target_email": target_email or getattr(target_user, "email", None),
            "previous_role": previous_role,
            "new_role": new_role,
            "actor_id": getattr(actor, "id", None) if actor and getattr(actor, "is_authenticated", False) else None,
            "ip_address": get_client_ip(request=request),
            "user_agent": (request.META.get("HTTP_USER_AGENT", "") or "")[:512],
        }
        record_access_event.delay(log_data=log_data)
    except Exception as e:
        log_exception(e)
