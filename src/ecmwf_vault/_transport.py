# SPDX-FileCopyrightText: 2026 European Centre for Medium-Range Weather Forecasts (ECMWF)
# SPDX-License-Identifier: Apache-2.0
"""One HTTPS GET to Vault, and a strict JSON parse.

Two reads are supported and they share the request: a KV v2 secret read, and a token
lookup of the caller's own token (``auth/token/lookup-self``), which answers with a
flat ``data`` object rather than the nested one a KV v2 read uses.

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

# The caller's own token. Not under the data mount: auth endpoints are fixed, whatever
# ECMWF_VAULT_MOUNT says. A token *can* be denied this — the default policy allows it, and a
# policy that replaces the default need not — which is why a refusal is reported as a refusal
# rather than as proof that the token is gone.
TOKEN_LOOKUP_PATH = "/v1/auth/token/lookup-self"
TOKEN_REFUSED_MESSAGE = (
    "the Vault token cannot look itself up (403); that is usually a token which has expired "
    "or been revoked, and can equally be a policy that does not allow a token to read itself")


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


def _lookup_data(document: Any) -> Dict[str, Any]:
    """Return the metadata mapping from a token lookup response.

    Every field is passed through as Vault sent it — this function checks the *shape* and
    nothing else, so a field this package has never heard of still reaches the caller.
    """
    if not isinstance(document, dict):
        raise VaultResponseError(SHAPE_MESSAGE)
    data = document.get("data")
    if not isinstance(data, dict):
        raise VaultResponseError(SHAPE_MESSAGE)
    return data


def _cubbyhole_fields(document: Any) -> Dict[str, Any]:
    """Return the field mapping from a cubbyhole read response.

    A cubbyhole read answers with a flat ``data`` object, like a token lookup, but its keys are
    used as names rather than read as metadata, so they are checked the way a KV v2 mapping's
    are. A null payload is refused rather than reported as no fields: a path that does not
    exist answers 404, so reaching here with nothing under ``data`` is a bad response.
    """
    if not isinstance(document, dict):
        raise VaultResponseError(SHAPE_MESSAGE)
    data = document.get("data")
    if not isinstance(data, dict):
        raise VaultResponseError(SHAPE_MESSAGE)
    for key in data:
        if not isinstance(key, str) or not key:
            raise VaultResponseError(SHAPE_MESSAGE)
    return data


def parse_fields(body: bytearray) -> Dict[str, Any]:
    """Parse a KV v2 read body into its field mapping, then wipe the buffer."""
    return _parse(body, _envelope)


def parse_cubbyhole_fields(body: bytearray) -> Dict[str, Any]:
    """Parse a cubbyhole read body into its field mapping, then wipe the buffer."""
    return _parse(body, _cubbyhole_fields)


def parse_token_info(body: bytearray) -> Dict[str, Any]:
    """Parse a token lookup body into its metadata mapping, then wipe the buffer.

    A lookup answers with a flat ``data`` object, one level shallower than a KV v2 read,
    so it needs its own shape check: :func:`_envelope` would reject it as malformed.
    """
    return _parse(body, _lookup_data)


def _parse(body: bytearray, shape) -> Dict[str, Any]:
    """Decode a Vault body with the strict hooks, wipe it, and apply ``shape`` to it."""
    try:
        document = json.loads(
            body, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except ValueError:
        raise VaultResponseError(INVALID_JSON_MESSAGE) from None
    finally:
        wipe(body)
    return shape(document)


def _close_connection(connection: Optional[http.client.HTTPSConnection]) -> None:
    if connection is not None:
        connection.close()


def _close_response(response: Optional[http.client.HTTPResponse]) -> None:
    """Close a response's file, ignoring one that is already closed or already broken.

    An error response is never read, and a response that outlives its connection keeps the
    socket's descriptor open — for as long as the raised exception, and the traceback that
    keeps this frame alive, does. That is a descriptor per refused request in any process that
    logs an exception or otherwise holds on to one. Closing the response in the ``finally``
    that closes the connection is what releases it *now* rather than at collection time.

    The ``OSError`` is swallowed because this runs while a refusal may already be on its way
    out, and a socket that is already broken must not take the place of the reason we are
    leaving.
    """
    if response is not None:
        try:
            response.close()
        except OSError:
            pass


def _get(target: str, host: str, port: int, token: str, timeout: float,
         context: ssl.SSLContext) -> bytearray:
    """One authenticated GET, returning the bounded body for the caller to parse and wipe."""
    connection = None
    response = None
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
        # The response before the connection, and both on every path out of here: a response
        # left to the collector holds the descriptor until nothing refers to the frame it is in.
        _close_response(response)
        _close_connection(connection)
    return body


def fetch_secret(host: str, port: int, target: str, token: str, timeout: float,
                 context: ssl.SSLContext) -> Dict[str, Any]:
    """Perform one Vault KV v2 read and return the secret's fields.

    Never reads an error body, and never puts the token or a response fragment
    into a message.
    """
    return parse_fields(_get(target, host, port, token, timeout, context))


def fetch_cubbyhole(host: str, port: int, target: str, token: str, timeout: float,
                    context: ssl.SSLContext) -> Dict[str, Any]:
    """Perform one cubbyhole read and return its fields.

    Same request as :func:`fetch_secret`; only the response shape differs, and the target is
    built by the caller because a cubbyhole has no mount to substitute.
    """
    return parse_cubbyhole_fields(_get(target, host, port, token, timeout, context))


def fetch_token_info(host: str, port: int, token: str, timeout: float,
                     context: ssl.SSLContext) -> Dict[str, Any]:
    """Read the token's own metadata from ``auth/token/lookup-self``.

    A refusal is re-raised with the lookup's own wording rather than the generic "cannot
    read this secret", because a 403 here is about the *token* rather than about a path:
    whatever the cause, this token cannot read its own details, and the message names the
    usual causes without pretending they are the whole list.
    """
    try:
        body = _get(TOKEN_LOOKUP_PATH, host, port, token, timeout, context)
    except VaultPermissionError:
        raise VaultPermissionError(TOKEN_REFUSED_MESSAGE) from None
    return parse_token_info(body)
