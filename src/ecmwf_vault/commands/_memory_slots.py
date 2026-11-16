# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""Memory files the child reaches by nickname.

A command holds a secret in a sealed anonymous memory file, and the child opens it through an
inherited descriptor — ``/proc/self/fd/<n>``, which the child resolves against *its own* table.
The number is chosen by the kernel and is nobody's business, so this maps the nickname the
operator typed to whatever number turned up, and rewrites the child's arguments before the
spawn.

Nothing here persists a nickname: it exists in this dict, in this process, for as long as the
child runs. It is not sent to Vault, not written anywhere, and does not reach the child at all
— the child receives the substituted path, which mentions only a number.

The name in ``ls -l /proc/<pid>/fd`` is a fixed caption from :mod:`ecmwf_vault._memory`
(``/memfd:ecmwf-vault-secret (deleted)``), not the nickname, and the nickname is never derived
from a field name returned by the server. Both rules keep a Vault writer out of text an
operator reads while debugging.
"""
from __future__ import annotations

import os
from typing import Dict, List, Sequence, Tuple

from ecmwf_vault import SecretMemoryFile

from . import _command_contract as contract


class MemorySlots:
    """Nicknamed sealed memory files, and the argument rewriting that refers to them."""

    def __init__(self) -> None:
        self._files: Dict[str, SecretMemoryFile] = {}

    def __bool__(self) -> bool:
        return bool(self._files)

    def __enter__(self) -> "MemorySlots":
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()

    def add(self, nickname: str, payload: bytes) -> None:
        """Hold ``payload`` in a sealed memory file under this nickname."""
        if not contract.IDENTIFIER.match(nickname):
            raise SystemExit(
                "%r is not usable as a memory-file name: use letters, digits and underscore, "
                "starting with a letter or underscore, because it has to survive being typed "
                "as {%s} in the command" % (nickname, nickname))
        if nickname in self._files:
            raise SystemExit("two memory files named %r; give them different names" % nickname)
        self._files[nickname] = SecretMemoryFile(payload)

    def path(self, nickname: str) -> str:
        """How a child opens this slot.

        Valid only in a process that inherited the descriptor, because ``self`` is the reader.
        """
        return "/proc/self/fd/%d" % self._files[nickname].fd

    def descriptors(self) -> Tuple[int, ...]:
        """The numbers to hand over, in the order they were added."""
        return tuple(memory.fd for memory in self._files.values())

    def names(self) -> Tuple[str, ...]:
        """The nicknames held, in the order they were added."""
        return tuple(self._files)

    def substitute(self, command: Sequence[str]) -> List[str]:
        """``command`` with each ``{nickname}`` replaced by its descriptor path.

        With nothing declared the argument list is returned as it arrived, which is what keeps
        the pass-through promise the commands document: substitution happens only to a caller
        who asked for it. Once a slot exists, a braced token naming anything else is a refusal
        rather than a silent pass-through — an argument of literal ``{aples}`` reaching the
        child fails as "no such file or directory", which reads like a broken descriptor rather
        than a typo.
        """
        arguments = list(command)
        if not self._files:
            return arguments
        for argument in arguments:
            # Refused only when the *whole* argument is a placeholder naming something
            # undeclared. An embedded one is indistinguishable from shell syntax like ${OUT},
            # which must pass through untouched, so the check cannot be as broad as the
            # substitution is.
            found = contract.PLACEHOLDER.fullmatch(argument)
            if found and found.group(1) not in self._files:
                raise SystemExit(
                    "%s is not a memory file this command was given; it has %s"
                    % (argument, ", ".join(
                        "{" + name + "}" for name in self._files) or "none"))
        return [contract.SUBSTITUTABLE.sub(
            lambda match: self.path(match.group(1)) if match.group(1) in self._files
            else match.group(0), argument) for argument in arguments]

    def close(self) -> None:
        """Release this process's descriptors. Call only once the child has finished."""
        for memory in self._files.values():
            memory.close()
        self._files.clear()


def environment_file_text(values: Dict[str, str]) -> bytes:
    """The env-file form of a variable mapping: one ``NAME=value`` line each, sorted.

    A value spanning lines is refused rather than quoted. Every format that reads these files
    handles quoting slightly differently, and getting it wrong yields a value that looks right
    and is not, so the honest answer is that a multi-line value does not fit in a line format.

    The bytes come from ``os.fsencode``, matching what the environment route would export.
    Strict UTF-8 would raise ``UnicodeEncodeError`` on a value that route accepts — a lone
    surrogate in the U+DC80 to U+DCFF range is exactly how an undecodable byte round-trips —
    and that exception object holds the text, so ``repr()`` of it contains the secret.
    """
    if not values:
        raise SystemExit("there are no variables to put in a memory file")
    for name, value in sorted(values.items()):
        if "\n" in value or "\r" in value:
            raise SystemExit(
                "%s holds a value spanning lines, which an environment file cannot represent; "
                "pass it with --mem-field instead" % name)
    return os.fsencode("".join("%s=%s\n" % (name, values[name])
                               for name in sorted(values)))
