# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.contrib.auth import login
from django.conf import settings

# Module imports
from plane.utils.host import base_host
from plane.utils.ip_address import get_client_ip
from plane.authentication.utils.audit import record_authentication_event
from plane.db.models import AuthenticationAuditLog


def user_login(request, user, is_app=False, is_admin=False, is_space=False):
    login(request=request, user=user)

    # If is admin cookie set the custom age
    if is_admin:
        request.session.set_expiry(settings.ADMIN_SESSION_COOKIE_AGE)

    device_info = {
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        "ip_address": get_client_ip(request=request),
        "domain": base_host(request=request, is_app=is_app, is_admin=is_admin, is_space=is_space),
    }
    request.session["device_info"] = device_info
    request.session.save()

    # Record the successful authentication for the audit trail (FedRAMP AU-2).
    origin = "admin" if is_admin else "space" if is_space else "app" if is_app else None
    record_authentication_event(
        request=request,
        event_type=AuthenticationAuditLog.EventType.SIGN_IN,
        user=user,
        origin=origin,
    )
    return
