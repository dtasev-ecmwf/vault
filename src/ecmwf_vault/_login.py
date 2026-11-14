# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Obtain a Vault token from a person, store it sealed, and reuse that flow on expiry.

A Vault service token lasts hours, so it runs out while someone is working. Two things answer
that. :func:`log_in` is what ``vault_login`` does: print the address to log in at, read a
token
without echoing it, check it with Vault, and write it sealed only once that works.
:func:`run_retrying_once_if_token_lookup_refused` is what the other commands do: run the
operation, and if Vault refuses the token, ask for a new one and try once more.

**A refusal is not proof of expiry.** Vault answers 403 both for a token that has gone and for
one that may not read the path it asked for, so the token is looked up before anything
replaced. A token that cannot look itself up is treated as gone; one that can is left alone and
the caller's error stands. Nothing is replaced before the operation, because a token refused
its own lookup may still be allowed to do the work.

**Asking needs a terminal.** The token file is the only source, so a prompt can always reach the
credential the next read will use — but a pipeline or a cron job has nobody to ask, gets that
explanation, and fails.

**Nothing here can print the token.** The prompt refuses outright if the terminal cannot disable
echo, rather than falling back to an echoed line. The check is the library's own lookup, which
withholds a token Vault reports as ``id``. No message is built from the token.
:func:`store_sealed_token` is the only write.
"""
from __future__ import annotations

import functools
import getpass
import os
import re
import sys
import warnings
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from . import _config, _sealed_token_file
from ._client import Vault
from ._errors import (
    VaultError,
    VaultPermissionError,
    VaultTokenInvalidError,
)
from ._policy import harden_process

# The marker a Vault service token carries, taken from the one place that decides what a token
# looks like: "is this a token" and "is this file sealed" are deliberately the same question in
# this package, so the rule is not written down twice.
TOKEN_PREFIX = _sealed_token_file.PLAINTEXT_PREFIX.decode("ascii")

WELCOME = (
    "Fetch your token by logging into %s. Once logged in, go to the top right on your user "
    "icon and click, then in the menu \"Copy token\" and paste it here. The token expiry "
    "date will be shown and it is stored encrypted")
TOKEN_PROMPT = "paste the token (it is not echoed): "
NOT_A_TOKEN = (
    "that does not look like a Vault token: one starts with %s and holds no spaces")
REFUSED = "Vault refused that token, so nothing was stored; paste another"
ABORTED = ("no token was entered (end of input, or an interrupt), so nothing was stored")
NO_TERMINAL_MESSAGE = (
    "there is no terminal to ask for a token on; run vault_login from a terminal")
CANNOT_HIDE_ECHO_MESSAGE = (
    "this terminal cannot hide what is typed, so the token would be shown on screen as you "
    "paste it; run vault_login on a terminal where it will not be")
STORED_WITH_EXPIRY = "the token was stored encrypted at %s; Vault says it expires at %s"
STORED_WITHOUT_EXPIRY = (
    "the token was stored encrypted at %s, and no usable expiry time was reported for it")

# What a 403 means is not settled until it is examined, so none of these is printed on a
# refusal alone — only once the token has proved that it cannot even describe itself. The
# phrasing keeps that in view, because "expired" is usually true and not certainly true.
TOKEN_LOOKUP_REFUSED = (
    "Vault refused to look the token up, which usually means it has expired or been revoked")
NO_TERMINAL_FOR_RENEWAL_HINT = (
    TOKEN_LOOKUP_REFUSED + "; there is no terminal to ask for a new one on — run vault_login "
    "from a terminal")

# Vault writes timestamps with up to nanosecond precision and a trailing ``Z``. Python's
# ``datetime.fromisoformat`` takes exactly three or six fractional digits and, before 3.11, no
# ``Z`` at all — so the text is normalised here rather than relying on the interpreter's
# version. Anything that will not parse is "no expiry", never an error.
_TRAILING_UTC_SUFFIX_PATTERN = re.compile(r"[Zz]$")
_FRACTION_PATTERN = re.compile(r"\.(\d+)")


def print_diagnostic(prefix: str, message: str) -> None:
    """Write one diagnostic line to stderr, under the command's prefix."""
    print("%s %s" % (prefix, message), file=sys.stderr)


def stdin_is_terminal() -> bool:
    """Whether there is a terminal to ask a question on.

    A ``stdin`` that cannot answer — a pipe, a closed file, no stream at all — must never be
    read as if a person were there, so this asks the stream rather than guessing.
    """
    stream = getattr(sys, "stdin", None)
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def require_terminal() -> None:
    """Refuse to ask for a token when there is nobody to ask.

    Checked on the way into the default prompt rather than around it, so that a run with no
    terminal fails with a sentence instead of reading whatever is on stdin as if it were a
    paste.
    """
    if not stdin_is_terminal():
        raise VaultError(NO_TERMINAL_MESSAGE)


def read_without_echo(prompt: str) -> str:
    """Read a line with the terminal's echo off, or refuse to read it at all.

    ``getpass`` falls back to reading an ordinary, *echoed* line when it cannot turn echo off:
    it warns and carries on. A warning is not enough here, because the whole promise of the
    prompt is that the token does not appear on the screen — so the warning is turned into a
    refusal, the fallback reads nothing, and the caller is told to use a real terminal.
    """
    with warnings.catch_warnings():
        # Within this block, the fallback warning is an error rather than a note. The caller's
        # own warning filters are left alone.
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise VaultError(CANNOT_HIDE_ECHO_MESSAGE) from None


def looks_like_a_token(entered: str) -> bool:
    """Whether what was typed could be a Vault service token.

    Two rules, and both are Vault's: a token starts with ``hvs.``, and it is characters that
    can go in an HTTP header. The second is checked here rather than left to the request,
    because the error a header library raises carries the value it could not encode.
    """
    if not entered.startswith(TOKEN_PREFIX):
        return False
    try:
        _config.validated(entered)
    except VaultTokenInvalidError:
        return False
    return True


def ask_for_token(read: Callable[[str], str], write: Callable[[str], None]) -> str:
    """Read a token without echo, asking again until what arrives looks like one.

    The end of input, or an interrupt, is a refusal rather than a loop: a person who has
    changed their mind should not have to fight the prompt.
    """
    while True:
        try:
            entered = read(TOKEN_PROMPT)
        except (EOFError, KeyboardInterrupt):
            raise VaultError(ABORTED) from None
        entered = entered.strip()
        if looks_like_a_token(entered):
            return entered
        write(NOT_A_TOKEN % TOKEN_PREFIX)


def verify_token(vault: Vault, token: str) -> Dict[str, Any]:
    """Ask Vault about ``token``. Raises if Vault refuses it or cannot be reached.

    The lookup is the library's own, so a token Vault reports as ``id`` is withheld here too
    and the answer can be printed without a credential in it.
    """
    if vault.harden:
        harden_process()
    return vault._lookup(token)


def log_in(*, prefix: str, token_path: Optional[str] = None,
           read: Optional[Callable[[str], str]] = None,
           write: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Ask for a token, check it with Vault, and store it sealed.

    ``read`` and ``write`` are the terminal, injected so that the flow can be driven without
    one. With no ``read`` injected the prompt is the terminal's own, and there has to be one:
    a run with nothing to ask on is refused rather than reading stdin as if it were a paste.

    A token Vault refuses is not stored, and the question is asked again; a Vault that cannot
    be reached at all ends the attempt, because asking again would not help.

    The address shown to log in at is the one this reads from — the configured Vault — so a
    login is never pointed at one server while its token is checked against another.
    """
    if read is None:
        require_terminal()
        read = read_without_echo
    write = write if write is not None else functools.partial(print_diagnostic, prefix)
    with Vault() as vault:
        write(WELCOME % (vault.base_url.rstrip("/") + "/"))
        while True:
            token = ask_for_token(read, write)
            try:
                info = verify_token(vault, token)
            except VaultPermissionError:
                write(REFUSED)
                continue
            break
    path = store_sealed_token(token, token_path=token_path)
    expire_time = reported_expiry(info)
    write(STORED_WITH_EXPIRY % (path, expire_time) if expire_time
          else STORED_WITHOUT_EXPIRY % path)
    return info


def reported_expiry(info: Dict[str, Any]) -> Optional[str]:
    """The expiry Vault reported, as one canonical ASCII timestamp, or None.

    The value arrives in a response and is printed, so it is **not** passed through as Vault
    wrote it: it is re-rendered from the instant it names. ``datetime.fromisoformat`` is
    about the separator and about how many fractional digits it will take — a response could
    hand back a non-ASCII separator that cannot even be printed as it arrived, or a fraction
    thousands of digits long — and a bounded, plain timestamp is what a line of diagnostics
    should hold. A value that does not name an instant at all yields None, so a response cannot
    put arbitrary text, which could be the token itself, into that line.
    """
    expire_time = info.get("expire_time")
    if not isinstance(expire_time, str):
        return None
    parsed = parse_expiry(expire_time)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def store_sealed_token(token: str, *, token_path: Optional[str] = None) -> str:
    """Write ``token`` sealed to the token file, and return the path it went to."""
    path = token_path if token_path is not None else _config.token_file_path()[0]
    _sealed_token_file.write(path, token)
    return path


def parse_expiry(text: str) -> Optional[datetime]:
    """A timestamp as Vault writes it, as an aware datetime, or None if it cannot be read.

    Only used to find out *which instant* a value names — the value itself is never printed or
    stored as it arrived — so leniency here is harmless: the caller re-renders the result.
    """
    value = text.strip()
    if not value:
        return None
    value = _TRAILING_UTC_SUFFIX_PATTERN.sub("+00:00", value)
    match = _FRACTION_PATTERN.search(value)
    if match:
        digits = (match.group(1) + "000000")[:6]
        value = value[:match.start()] + "." + digits + value[match.end():]
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def run_retrying_once_if_token_lookup_refused(operation: Callable[[], Any],
                                              *, prefix: str) -> Any:
    """Run ``operation``, and if Vault refuses the token, ask for a new one and try once more.

    Nothing is replaced before the operation runs. A token can be refused this endpoint's own
    lookup and still be allowed to do the work, so a lookup refusal is evidence about the
    *lookup* — and the thing worth knowing, that the caller's request was refused, is only
    known once it has been refused. The order here is deliberate: the operation first, then the
    lookup, then — if the token cannot describe itself and can be replaced — one retry.

    If the retry fails too, the second failure is handed back rather than examined again.
    """
    try:
        return operation()
    except VaultPermissionError:
        if not replace_token_if_lookup_refused(prefix=prefix):
            raise
    return operation()


def replace_token_if_lookup_refused(*, prefix: str) -> bool:
    """Whether a new token was obtained, so the caller should try its operation again.

    The order is deliberate. The token is examined first, because the refusal alone does not
    say whether the token has gone or merely may not read that path — and a diagnostic that
    called a healthy token expired would be worse than none. Only a token that cannot be
    looked up either is treated as gone, and then a missing terminal is named rather than
    waited for, because a command with nobody at the keyboard must not hang on a prompt.
    """
    if not token_lookup_refused():
        return False
    if not stdin_is_terminal():
        print_diagnostic(prefix, NO_TERMINAL_FOR_RENEWAL_HINT)
        return False
    log_in(prefix=prefix)
    return True


def token_lookup_refused() -> bool:
    """Whether Vault refused to let the token describe itself.

    That is what an expired or revoked token cannot do, and a token that *can* describe itself
    is a token that may not read the path it asked for — so this, and not a guess at expiry, is
    what decides whether asking for a new one is worth anything. Any other failure — an
    unreachable Vault, a configuration the instance refuses — is not evidence about the token,
    so it is not treated as one either.
    """
    try:
        with Vault() as vault:
            vault.token_info()
    except VaultPermissionError:
        return True
    except VaultError:
        return False
    return False
