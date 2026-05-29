# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.views import View
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.utils import timezone

# Module imports
from plane.authentication.utils.host import base_host, user_ip
from plane.authentication.utils.audit import record_authentication_event
from plane.db.models import AuthenticationAuditLog, User
from plane.utils.path_validator import get_safe_redirect_url


class SignOutAuthSpaceEndpoint(View):
    def post(self, request):
        next_path = request.POST.get("next_path")

        # Get user
        try:
            user = User.objects.get(pk=request.user.id)
            user.last_logout_ip = user_ip(request=request)
            user.last_logout_time = timezone.now()
            user.save()
            # Record the sign-out for the audit trail (FedRAMP AU-2).
            record_authentication_event(
                request=request,
                event_type=AuthenticationAuditLog.EventType.SIGN_OUT,
                user=user,
                origin="space",
            )
            # Log the user out
            logout(request)
            url = get_safe_redirect_url(base_url=base_host(request=request, is_space=True), next_path=next_path)
            return HttpResponseRedirect(url)
        except Exception:
            url = get_safe_redirect_url(base_url=base_host(request=request, is_space=True), next_path=next_path)
            return HttpResponseRedirect(url)
