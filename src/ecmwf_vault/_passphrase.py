# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The passphrase the token file is sealed with, derived from the account.

``vault_login`` seals the token file with a passphrase built from facts about the account
running it: the account name with ``$`` between its characters, then ``_``, then the uid and
gid multiplied. For ``madt`` with uid 4509 and gid 5000 that is ``m$a$d$t_22545000``.

**What this is not.** Every part of it is readable by anyone on the machine — the account name
and the uid and gid are in the user database, world-readable — and the scheme itself is in this
package. So the sealed file is *not* a boundary against another user of the same host; anyone
who can read the file can also derive the passphrase and open it. What it buys is that the
token is never a *string* on disk: searching a home directory or a backup for ``hvs.`` does not
find it, a copy of the file taken off the host needs the scheme and gpg rather than being the
token itself, and a person looking over your shoulder at a file listing sees nothing.

That is the trade the token's short life makes worth it. Two consequences are worth knowing:
a copy of the file is recoverable by whoever knows this derivation and can read the file, and
a change to the account's uid or gid renames the passphrase — the file then cannot be read and
the answer is to log in again.

The upside is that it works with nothing: no agent, no terminal, no prompt. A derived
passphrase can be handed to gpg on a pipe, which is why ``vaultenv`` in a cron job can read a
token that was never written down.
"""
from __future__ import annotations

import getpass
import os
import pwd

from ._errors import VaultError

SEPARATOR = "$"
SUFFIX_SEPARATOR = "_"

DERIVATION_MESSAGE = (
    "the account could not be determined, so the token file's passphrase cannot be derived: "
    "its name, uid and gid are what it is built from")


def account_name() -> str:
    """The account's name, from the user database rather than from the environment.

    :func:`getpass.getuser` checks ``LOGNAME``, ``USER`` and friends first, and those are
    environment variables: a passphrase that changed with an exported variable would make the
    token file unreadable for no reason at all. The user database is where the account
    actually is, so that is what this asks.

    A uid with no entry — a container running as a random uid, usually — falls back to what
    the environment says, because a passphrase from the environment still works within one
    process tree, and refusing to run at all would be worse.
    """
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        try:
            return getpass.getuser()
        except KeyError:
            raise VaultError(DERIVATION_MESSAGE) from None


def account_label() -> str:
    """What the passphrase is derived from, for a message that has to explain a failure."""
    return "%s (uid %d, gid %d)" % (account_name(), os.getuid(), os.getgid())


def for_this_account() -> str:
    """The passphrase for this account's token file.

    Not a secret, and not treated as one: see the module docstring. It exists so that the token
    file can be sealed without asking anyone for anything.
    """
    return "%s%s%d" % (SEPARATOR.join(account_name()), SUFFIX_SEPARATOR,
                       os.getuid() * os.getgid())
