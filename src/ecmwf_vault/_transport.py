# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""One HTTPS GET to the Vault KV v2 read endpoint, and a strict JSON parse.

``http.client`` is used instead of ``urllib.request`` on purpose: it has no
proxy support (so ``HTTPS_PROXY`` cannot redirect a token-bearing request) and
it never follows a redirect (so the token header cannot be replayed to another
host). Exactly one request is sent per call.
"""
from __future__ import annotations

import http.client
import json
import ssl
from typing import Any, Dict, Optional

from ._errors import (
    SecretNotFoundError,
    VaultPermissionError,
    VaultResponseError,
    VaultUnavailableError,
    VaultError,
)

MAX_RESPONSE = 256 * 1024
CHUNK = 8192

CA_BUNDLE_MESSAGE = (
    "the Vault CA bundle could not be loaded (ECMWF_VAULT_CA_BUNDLE)")

SHAPE_MESSAGE = "unexpected Vault response shape"
INVALID_JSON_MESSAGE = "the Vault response is not valid JSON"
DUPLICATE_MESSAGE = "the Vault response contains a duplicate field"
CONSTANT_MESSAGE = "the Vault response contains a non-finite number"
SIZE_MESSAGE = "the Vault response exceeds the size limit"
DELETED_MESSAGE = "the secret has no readable version"
REQUEST_MESSAGE = "the Vault request failed"


# OpenSSL's X509_V_FLAG_PARTIAL_CHAIN and X509_V_FLAG_X509_STRICT. Python's ssl
# module exposes them as VERIFY_X509_PARTIAL_CHAIN (3.10+) and
# VERIFY_X509_STRICT (3.13+), but the flag bits have been fixed in OpenSSL since
# long before that, so an older interpreter linked against a modern OpenSSL can
# still use them. A test pins these numbers against the ssl constants wherever
# those exist.
_PARTIAL_CHAIN = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0x00080000)
_X509_STRICT = getattr(ssl, "VERIFY_X509_STRICT", 0x00000020)
# X509_V_FLAG_PARTIAL_CHAIN first appears in OpenSSL 1.0.2 (it is absent from
# 1.0.1); X509_V_FLAG_X509_STRICT has been 0x20 since 1.0.0. Setting a bit the
# linked library does not know would be a silent no-op at best, so PARTIAL_CHAIN
# is used only when the library is new enough for it to mean something. Every
# OpenSSL any supported CPython links to (1.1.0+ from CPython 3.9) has it.
_PARTIAL_CHAIN_SINCE = (1, 0, 2)


def _verification_hardening() -> int:
    """The certificate-verification flags CPython's TLS factory adds.

    Mirrors the current factory's own line, ``verify_flags |=
    (VERIFY_X509_PARTIAL_CHAIN | VERIFY_X509_STRICT)``.

    ``STRICT`` is always set: it only makes OpenSSL more conservative, and the
    flag has existed since OpenSSL 1.0.0. ``PARTIAL_CHAIN`` is set whenever the
    linked OpenSSL understands it, which is what makes a CA bundle holding an
    *intermediate* usable as a trust anchor at all (otherwise OpenSSL insists on
    a self-signed root in the store) — a stated guarantee, so it must not depend
    on an interpreter exposing the constant. A test asserts the context is never
    weaker than the running platform's factory, so a future Python that adds a
    flag fails the suite instead of silently weakening this.
    """
    flags = _X509_STRICT
    if ssl.OPENSSL_VERSION_INFO >= _PARTIAL_CHAIN_SINCE:
        flags |= _PARTIAL_CHAIN
    return flags


def create_context(ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    """Build the TLS context used for every Vault request.

    Assembled rather than taken from ``ssl.create_default_context()``, because
    that helper **reads ``SSLKEYLOGFILE`` and opens the file it names while it
    builds the context**: the file would already be on disk before any
    ``keylog_filename`` pin could take effect, and a value naming a missing or
    unwritable path would make context creation raise. A TLS key log is a
    plaintext record of the session key and would expose both the token and the
    secret in any captured session. ``SSLContext`` itself does not read the
    variable, so this function never has to touch the process environment —
    which also means it cannot disturb a caller's own TLS setup.

    Everything the factory would have set is set here explicitly: certificate
    and hostname verification, TLS 1.2 as the floor (the factory has not always
    raised it, and the guarantee must not depend on the linked OpenSSL's
    default), the verification flags above, and the trust store — a CA bundle in
    place of the system store, so an override cannot widen trust to every CA the
    host happens to know. A bundle that cannot be loaded is a fixed error.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= _verification_hardening()
    if ca_bundle is not None:
        try:
            context.load_verify_locations(cafile=ca_bundle)
        except (OSError, ssl.SSLError):
            raise VaultError(CA_BUNDLE_MESSAGE) from None
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    try:
        context.keylog_filename = None
    except (AttributeError, NotImplementedError):  # pragma: no cover - old OpenSSL
        pass
    return context


def wipe(buffer: bytearray) -> None:
    """Overwrite a buffer in place with zero bytes.

    Equal-length slice assignment does not reallocate, so this is a real
    best-effort overwrite of that buffer. It is not erasure of the Python
    copies derived from it (see the README).
    """
    buffer[:] = bytes(len(buffer))


def _status_error(status: int) -> VaultError:
    if status == 400:
        return VaultResponseError("the Vault request was rejected (400)")
    if status == 403:
        return VaultPermissionError("the Vault token cannot read this secret (403)")
    if status == 404:
        return SecretNotFoundError("the secret was not found (404)")
    if status == 429:
        return VaultUnavailableError("Vault is busy (429)")
    return VaultUnavailableError("Vault returned status %d" % status)


def _headers(token: str) -> Dict[str, str]:
    return {
        "X-Vault-Token": token,
        "Accept": "application/json",
        "Content-Length": "0",
        "Connection": "close",
    }


def _read_bounded(response: http.client.HTTPResponse) -> bytearray:
    body = bytearray()
    while True:
        chunk = response.read(CHUNK)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAX_RESPONSE:
            wipe(body)
            raise VaultResponseError(SIZE_MESSAGE)
    return body


def _unique_object(pairs: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VaultResponseError(DUPLICATE_MESSAGE)
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise VaultResponseError(CONSTANT_MESSAGE)


def _envelope(document: Any) -> Dict[str, Any]:
    """Return the field mapping from a KV v2 read response."""
    if not isinstance(document, dict):
        raise VaultResponseError(SHAPE_MESSAGE)
    outer = document.get("data")
    if not isinstance(outer, dict) or "data" not in outer:
        raise VaultResponseError(SHAPE_MESSAGE)
    inner = outer["data"]
    if inner is None:
        # A KV v2 entry whose version is deleted or destroyed answers 200 with
        # a null payload; that is "no secret here", not a malformed response.
        raise SecretNotFoundError(DELETED_MESSAGE)
    if not isinstance(inner, dict):
        raise VaultResponseError(SHAPE_MESSAGE)
    for key in inner:
        if not isinstance(key, str) or not key:
            raise VaultResponseError(SHAPE_MESSAGE)
    return inner


def parse_fields(body: bytearray) -> Dict[str, Any]:
    """Parse a KV v2 read body into its field mapping, then wipe the buffer."""
    try:
        document = json.loads(
            body, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except ValueError:
        raise VaultResponseError(INVALID_JSON_MESSAGE) from None
    finally:
        wipe(body)
    return _envelope(document)


def _close(connection: Optional[http.client.HTTPSConnection]) -> None:
    if connection is not None:
        connection.close()


def fetch_secret(host: str, port: int, target: str, token: str, timeout: float,
                 context: ssl.SSLContext) -> Dict[str, Any]:
    """Perform one Vault read and return the secret's fields.

    Never reads an error body, and never puts the token or a response fragment
    into a message.
    """
    connection = None
    try:
        connection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=context)
        connection.request("GET", target, headers=_headers(token))
        response = connection.getresponse()
        status = response.status
        if status != 200:
            raise _status_error(status)
        body = _read_bounded(response)
    except (OSError, http.client.HTTPException) as error:
        raise VaultUnavailableError(
            "%s: %s" % (REQUEST_MESSAGE, type(error).__name__)) from None
    finally:
        _close(connection)
    return parse_fields(body)
