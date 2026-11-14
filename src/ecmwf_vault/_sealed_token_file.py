# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The token file: a token sealed with the passphrase derived from the account.

Two things read and write ``~/.ecmwf-vault/token``, and both come through here:

* the library, for which the file is one of the token sources — including *sealing a file that
  was found in the clear*, so a token dropped in by hand does not stay that way;
* ``vault_login``, which obtains a new token and writes it.

gpg does the encryption. The passphrase goes to it on a **pipe** — never an argument, never the
environment — and gpg is run ``--batch`` with its pinentry in loopback mode, so there is no
prompt and no agent: this works in a cron job.

Nothing here decides whether something *is* a token; that is :mod:`ecmwf_vault._config`'s
business, and the two are kept apart so each can be read on its own. What is here is the
format — what a sealed file looks like, how to make one, and how to tell one from a token
sitting in the clear.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import List

from . import _environment, _passphrase
from ._errors import VaultError, VaultTokenFileError

# `gpg` where it is, `gpg2` where that is the only name it has. Resolved to a path so that a
# failure can say what was looked for, and so nothing named in a message is a bare relative
# name that would mean something else from another directory.
TOOL_NAMES = ("gpg", "gpg2")

# What a Vault service token starts with. A sealed file starts with gpg's message header
# instead, so one prefix is enough to tell the two apart — which is why "does this look like a
# token" and "is this file sealed" turn out to be the same question.
PLAINTEXT_PREFIX = b"hvs."

MODE = 0o600
DIRECTORY_MODE = 0o700

# A token is tens of bytes and its cipher a few hundred. The bound is applied while reading, and
# a tool that filled the pipe is killed before waiting, so nothing here can deadlock.
MAX_OUTPUT = 4096

TOOL_MISSING_MESSAGE = (
    "no %s was found on PATH, and the token file is read and written with it — install gpg")
TOOL_FAILED_MESSAGE = (
    "the token file's encryption tool failed, and it printed nothing this package can use")
UNSEAL_FAILED_MESSAGE = (
    "the token file could not be opened: it is sealed with a passphrase derived from an "
    "account, so a file written by a different account or on a different machine cannot be "
    "read here (this is %s) — run vault_login to fetch a new token")
CLEANUP_MESSAGE = (
    "%s — and the temporary file %s could not be removed either; it holds the sealed token and "
    "nothing else names it, so remove it yourself")


def plaintext(content: bytes) -> bool:
    """Whether ``content`` is a token in the clear rather than a sealed one."""
    return content.strip().startswith(PLAINTEXT_PREFIX)


def tool() -> str:
    """The gpg to run, as a path. Raises if there is none."""
    for name in TOOL_NAMES:
        found = shutil.which(name)
        if found is not None:
            return found
    raise VaultError(TOOL_MISSING_MESSAGE % " or ".join(TOOL_NAMES))


def gpg_arguments(*, sealing: bool) -> List[str]:
    """gpg's arguments for sealing or unsealing, before the passphrase pipe is added.

    ``--batch`` and loopback mode together mean gpg asks nobody for anything, which is what
    makes this work without a terminal. ``--output -`` is explicit so that a gpg.conf carrying
    an ``output`` setting cannot send a *decrypted token* to a file instead of to us. The
    passphrase pipe is appended by :func:`run`, which is the only thing that knows its number.

    ``--quiet`` is here because gpg narrates a *successful* decrypt — "AES256.CFB encrypted
    data", "encrypted with 1 passphrase" — to stderr, and every command that reads the token
    file decrypts it, so those two lines would appear on every single invocation. gpg still
    prints what went wrong: informational messages are what this drops, an error is not.
    """
    if sealing:
        return ["--batch", "--quiet", "--yes", "--symmetric", "--cipher-algo", "AES256",
                "--pinentry-mode", "loopback", "--output", "-"]
    return ["--batch", "--quiet", "--pinentry-mode", "loopback", "--decrypt", "--output", "-"]


def run(tool_path: str, gpg_arguments_list: List[str], *, stdin: bytes,
        passphrase: str) -> bytes:
    """Run gpg, returning its stdout. The passphrase reaches it on a pipe and nowhere else."""
    read_fd, write_fd = os.pipe()
    try:
        # Written before the fork: a pipe that size cannot fill, so there is nothing to wait for
        # and no way to deadlock against a tool that has not read it yet.
        os.write(write_fd, passphrase.encode("utf-8"))
    finally:
        os.close(write_fd)
    try:
        try:
            process = subprocess.Popen(
                [tool_path] + gpg_arguments_list + ["--passphrase-fd", str(read_fd)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, pass_fds=(read_fd,),
                env=_environment.child_environment())
        except OSError:
            raise VaultError(TOOL_FAILED_MESSAGE) from None
    finally:
        os.close(read_fd)
    try:
        try:
            process.stdin.write(stdin)
        except BrokenPipeError:
            # The tool gave up without reading; its exit status is what says so below.
            pass
        finally:
            _close_quietly(process.stdin)
        output = process.stdout.read(MAX_OUTPUT + 1)
        if len(output) > MAX_OUTPUT:
            process.kill()
            process.wait()
            raise VaultError(TOOL_FAILED_MESSAGE)
        if process.wait() != 0:
            raise VaultError(TOOL_FAILED_MESSAGE)
    finally:
        process.stdout.close()
    return output


def seal(token: str) -> bytes:
    """The sealed form of ``token``."""
    return run(tool(), gpg_arguments(sealing=True), stdin=token.encode("ascii"),
               passphrase=_passphrase.for_this_account())


def unseal(content: bytes) -> str:
    """The token inside sealed ``content``, or raise.

    The message on failure says what the file is sealed *with*, because the likeliest reason a
    sealed token file will not open is that it was written by another account or on another
    machine — and "wrong passphrase" would send someone looking for a passphrase to type. A
    missing tool is not that, so it is resolved before this and keeps its own message.
    """
    failed = UNSEAL_FAILED_MESSAGE % _passphrase.account_label()
    tool_path = tool()
    try:
        output = run(tool_path, gpg_arguments(sealing=False), stdin=content,
                     passphrase=_passphrase.for_this_account())
    except VaultError:
        raise VaultTokenFileError(failed) from None
    try:
        text = output.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise VaultTokenFileError(failed) from None
    if not text:
        raise VaultTokenFileError(failed)
    return text


def write(path: str, token: str) -> None:
    """Write ``token`` sealed, at mode 600, replacing whatever is at ``path``.

    A replacement rather than an install that refuses: the token file is *meant* to be replaced
    — by a new login, or by sealing a file found in the clear — and ``os.replace`` makes that
    one atomic step, so unlike an install there is no window with two names in it and a reader
    sees the old file or the new one. Even the temporary holds the sealed form, so a process
    killed mid-write leaves a cipher behind rather than a token.
    """
    payload = seal(token)
    directory = os.path.dirname(os.path.realpath(path))
    if not os.path.isdir(directory):
        # The mode the token file's own policy requires: a looser directory would be refused
        # when the file is next read.
        os.makedirs(directory, mode=DIRECTORY_MODE, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".token-", dir=directory)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
        os.chmod(temporary, MODE)
        os.replace(temporary, path)
    except BaseException as error:
        try:
            os.unlink(temporary)
        except OSError:
            # Raising the original on its own would leave a file nobody knows about behind it.
            raise VaultTokenFileError(CLEANUP_MESSAGE % (error, temporary)) \
                from error
        raise


def _close_quietly(stream) -> None:
    """Close a pipe to a tool that may already be gone, ignoring a broken pipe."""
    try:
        stream.close()
    except BrokenPipeError:
        pass
