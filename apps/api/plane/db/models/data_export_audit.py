# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.db import models

from .base import BaseModel


class DataExportAuditLog(BaseModel):
    """Append-only audit trail of bulk data-export events.

    Records requests to extract data out of the system (issue exports,
    analytics exports) to support FedRAMP AU-2 (auditable events) and
    accountability for data leaving the boundary. Rows are written, never
    updated or deleted by application code; ship this table to an in-boundary
    SIEM for retention/alerting.

    The actor (who requested the export) is captured by BaseModel.created_by;
    the fields below describe what was requested.
    """

    class ExportType(models.TextChoices):
        ISSUES = "ISSUES", "Issues export"
        ANALYTICS = "ANALYTICS", "Analytics export"

    export_type = models.CharField(max_length=32, choices=ExportType.choices, db_index=True)
    # Output format: csv, xlsx, json (issue exports); blank for analytics.
    provider = models.CharField(max_length=32, null=True, blank=True)

    workspace = models.ForeignKey(
        "db.Workspace",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="data_export_audit_logs",
    )
    # Number of projects in scope of the export (0/blank means workspace-wide).
    project_count = models.PositiveIntegerField(null=True, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, null=True, blank=True)

    class Meta:
        verbose_name = "Data Export Audit Log"
        verbose_name_plural = "Data Export Audit Logs"
        db_table = "data_export_audit_logs"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["export_type", "-created_at"]),
            models.Index(fields=["workspace", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.export_type} {self.provider or ''}".strip()
