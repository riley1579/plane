# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.conf import settings
from django.db import models

from .base import BaseModel


class AuthenticationAuditLog(BaseModel):
    """Append-only audit trail of authentication events.

    Records security-relevant identity events (sign-in, sign-out, sign-up,
    failures) to support FedRAMP AU-2/AC-7 and ITAR access-accountability
    requirements. Rows are written, never updated or deleted by application
    code; ship this table to an in-boundary SIEM for retention/alerting.
    """

    class EventType(models.TextChoices):
        SIGN_IN = "SIGN_IN", "Sign in"
        SIGN_UP = "SIGN_UP", "Sign up"
        SIGN_OUT = "SIGN_OUT", "Sign out"
        SIGN_IN_FAILED = "SIGN_IN_FAILED", "Sign in failed"

    event_type = models.CharField(max_length=32, choices=EventType.choices, db_index=True)
    # Nullable: a failed sign-in may not resolve to a known user.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="auth_audit_logs",
    )
    # Captured separately from the FK so the record survives user deletion and
    # so failed attempts against unknown/typo'd addresses are still attributable.
    email = models.CharField(max_length=255, null=True, blank=True)
    # Login medium: email, magic-code, google, github, gitlab, gitea, oidc, ...
    medium = models.CharField(max_length=32, null=True, blank=True)
    # Which app the event originated from: app, admin, space.
    origin = models.CharField(max_length=16, null=True, blank=True)
    # On failure, the authentication error code (see authentication/adapter/error.py).
    error_code = models.CharField(max_length=64, null=True, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, null=True, blank=True)

    class Meta:
        verbose_name = "Authentication Audit Log"
        verbose_name_plural = "Authentication Audit Logs"
        db_table = "authentication_audit_logs"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["event_type", "-created_at"]),
            models.Index(fields=["user", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} {self.email or self.user_id or ''}".strip()
