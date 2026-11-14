# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The environment this package hands to a child process."""
from __future__ import annotations

import os
from typing import Dict

# A token in the environment is not passed to a child. Nothing in this package reads this name,
# but an older copy of it running under a command does, and a child is not given a credential by
# default.
LEGACY_TOKEN_ENV = "ECMWF_VAULT_TOKEN"


def child_environment() -> Dict[str, str]:
    """This process's environment, without ``ECMWF_VAULT_TOKEN``."""
    environment = dict(os.environ)
    environment.pop(LEGACY_TOKEN_ENV, None)
    return environment
