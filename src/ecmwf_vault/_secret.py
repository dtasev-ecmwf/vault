# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""The opaque wrapper that every value read from the Vault is returned in.

A caller handed a plain ``str`` can put a secret on disk by accident —
``open(path, "w").write(secret)``, ``json.dumps({"pw": secret})``,
``os.environ["PW"] = secret``, ``subprocess.run(["cmd", secret])``. Every one of
those needs a real ``str``, so returning something that is *not* a ``str`` turns
that whole accident surface into an explicit ``reveal()``.

A ``str`` *subclass* does not work, which is the trap this class exists to avoid:
``TextIOWrapper.write`` accepts any ``str`` subclass and copies its data without
ever calling ``__str__``, so ``handle.write(secret)`` would quietly succeed.
Masking ``__str__`` also does not work, for the same reason.

This is a guard-rail, not a sandbox, and the README says so: ``reveal()`` is right
there, ``_value`` is reachable, and ``os.write`` on a descriptor, a C extension or
another process bypass it entirely. What it removes is the accident. The way out —
``reveal()``, or ``Vault.memory_file()`` to hand the secret to a child process
without a file ever existing — has to come from the documentation, because a refusal
raised inside CPython (a file write, a serialiser, a child process argument) cannot
name it.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from ._errors import VaultError

MASK = "<Secret>"
REVEAL_MESSAGE = (
    "this is a Secret, not a str: call Secret.reveal() to get the value, or "
    "Vault.memory_file() to hand it to a child process without a file")
ENCODE_MESSAGE = REVEAL_MESSAGE
PICKLE_MESSAGE = (
    "a Secret refuses to be pickled or copied: call Secret.reveal() first, so "
    "that putting it on disk is a deliberate act")


class Secret:
    """A value read from the Vault that cannot be used as a string by accident.

    Anything that merely *renders* it shows ``<Secret>``: ``str``, ``repr``,
    f-strings, ``%``-formatting, :meth:`format` and a logging handler. Anything that
    needs the text itself is refused, so it cannot be written to a file or a stream:
    no ``encode``, no pickling (which would otherwise turn it into bytes a caller
    could write out), no ``len``, no concatenation. ``reveal()`` and
    ``revealed()`` are the only ways to the value.
    """

    __slots__ = ("_value",)

    def __init__(self, value: Any) -> None:
        self._value = value

    def reveal(self) -> Any:
        """Return the value itself. Deliberate, and easy to grep for."""
        return self._value

    @contextmanager
    def revealed(self) -> Iterator[Any]:
        """Yield the value, so it is used inside one explicit block.

            with secret.revealed() as password:
                connect(password)
        """
        yield self._value

    def encode(self, *arguments: Any, **keywords: Any) -> bytes:
        """Refuse, with a pointer at ``reveal()``.

        ``encode`` is the one string method callers reach for often enough
        (hashing, size checks) that a bare ``AttributeError`` would teach
        nothing.
        """
        raise VaultError(ENCODE_MESSAGE)

    def __reduce__(self) -> Any:
        # pickling and copying would both produce the plaintext bytes, which is
        # another way to end up with the secret in a file.
        raise VaultError(PICKLE_MESSAGE)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return bool(self._value == other._value)
        return bool(self._value == other)

    def __hash__(self) -> int:
        return hash(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __str__(self) -> str:
        return MASK

    def __repr__(self) -> str:
        return MASK

    def __format__(self, specification: str) -> str:
        # Masking rather than raising: an f-string can only ever carry the mask to
        # a disk, and printing "<Secret>" in a log is what should happen.
        return MASK
