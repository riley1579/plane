# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Air-gap mode helpers.

When ``AIRGAP=1`` is set in the environment, the instance is running inside a
disconnected / no-egress boundary (e.g. an ITAR / FedRAMP-High enclave). In that
mode every code path that would otherwise reach a public, out-of-boundary
endpoint must fail safe (no-op) rather than attempt the call.

This is defense-in-depth: the network boundary itself should already deny
egress, but guarding in code means accidental calls fail fast and are caught in
dev/test instead of silently timing out in production.
"""

import os


def is_airgap() -> bool:
    """Return True when the instance is configured for air-gapped operation."""
    return os.environ.get("AIRGAP", "0") == "1"
