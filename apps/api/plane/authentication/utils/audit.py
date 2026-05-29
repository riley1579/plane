# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Helpers for recording authentication audit events.

Thin wrapper around the async ``record_auth_event`` task so call sites in the
authentication views/utils stay one-liners and never block the request path.
"""

# Module imports
from plane.bgtasks.auth_audit_task import record_auth_event
from plane.utils.exception_logger import log_exception
from plane.utils.ip_address import get_client_ip


def record_authentication_event(
    request,
    event_type,
    user=None,
    email=None,
    medium=None,
    origin=None,
    error_code=None,
):
    """Enqueue an authentication audit event.

    Best-effort: any failure to capture/enqueue is logged and swallowed so it
    can never break the authentication flow it is observing.
    """
    try:
        log_data = {
            "event_type": event_type,
            "user_id": getattr(user, "id", None),
            "email": email or getattr(user, "email", None),
            "medium": medium,
            "origin": origin,
            "error_code": str(error_code) if error_code is not None else None,
            "ip_address": get_client_ip(request=request),
            "user_agent": (request.META.get("HTTP_USER_AGENT", "") or "")[:512],
        }
        record_auth_event.delay(log_data=log_data)
    except Exception as e:
        log_exception(e)
