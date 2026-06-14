# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.conf import settings
from django.db import models

from .base import BaseModel


class AccessAuditLog(BaseModel):
    """Append-only audit trail of access-management events.

    Records security-relevant authorization changes (member added/removed,
    role changed) at the workspace and project level to support FedRAMP AC-2
    (account management) and AC-6 (least privilege), and ITAR access
    accountability. Rows are written, never updated or deleted by application
    code; ship this table to an in-boundary SIEM for retention/alerting.

    The actor (who made the change) is captured by BaseModel.created_by; the
    fields below capture the target of the change.
    """

    class EventType(models.TextChoices):
        MEMBER_ADDED = "MEMBER_ADDED", "Member added"
        MEMBER_REMOVED = "MEMBER_REMOVED", "Member removed"
        ROLE_CHANGED = "ROLE_CHANGED", "Role changed"

    class Scope(models.TextChoices):
        WORKSPACE = "WORKSPACE", "Workspace"
        PROJECT = "PROJECT", "Project"

    event_type = models.CharField(max_length=32, choices=EventType.choices, db_index=True)
    scope = models.CharField(max_length=16, choices=Scope.choices)

    workspace = models.ForeignKey(
        "db.Workspace",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_audit_logs",
    )
    # Nullable: project-scoped events set this; workspace-scoped events leave it null.
    project = models.ForeignKey(
        "db.Project",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_audit_logs",
    )
    # The member whose access changed (the target). Nullable + SET_NULL so the
    # record survives user deletion; the email is captured separately for the
    # same reason.
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_audit_target_logs",
    )
    target_email = models.CharField(max_length=255, null=True, blank=True)

    # Roles use the same integer scale as ProjectMember/WorkspaceMember.role
    # (e.g. 5 Guest, 15 Member, 20 Admin). Both nullable: a role change records
    # both old and new; add/remove records only the role at the time.
    previous_role = models.PositiveSmallIntegerField(null=True, blank=True)
    new_role = models.PositiveSmallIntegerField(null=True, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, null=True, blank=True)

    class Meta:
        verbose_name = "Access Audit Log"
        verbose_name_plural = "Access Audit Logs"
        db_table = "access_audit_logs"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["event_type", "-created_at"]),
            models.Index(fields=["workspace", "-created_at"]),
            models.Index(fields=["target_user", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} {self.scope} {self.target_email or self.target_user_id or ''}".strip()
