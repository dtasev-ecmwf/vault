# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The commands this package installs.

Two console scripts — ``vaultenv`` and ``kubectl_vault`` — one module each, mapped in
``pyproject.toml``. They are the package's only entry points, and they are deliberately
*not* an API: importing one is not supported, and only its :func:`main` is meant to be
called. Everything a caller should use lives in :mod:`ecmwf_vault` itself, which imports
nothing from here.

The two are independent commands — different arguments, different secrets, different
things done with them — so they share only what any command must do identically, which is
:mod:`ecmwf_vault.commands._command_contract`.
"""
