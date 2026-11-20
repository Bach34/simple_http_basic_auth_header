"""Parse and build HTTP Basic auth headers per RFC 7617 / RFC 2045.

Why this exists
---------------
The ``Authorization: Basic`` scheme is small but the surrounding parsing is
not: base64 payloads may be split over several lines, the ``charset``
parameter is defined only for the challenge and only for UTF-8, and header
field names are case-insensitive.  This module keeps the rules in one place
and makes the accepted surface explicit instead of relying on ad-hoc string
slicing at each call site.

Design decisions worth knowing
------------------------------
* ``parse_authorization`` requires the scheme to be ``Basic`` and accepts
  the base64 payload with any amount of ASCII whitespace, because RFC 2045
  allows folded base64 and real-world proxies inject line breaks.
* The ``charset`` parameter is only meaningful on the challenge side.  A
  challenge without ``charset`` is treated as ISO-8859-1, which is the
  historical default; a challenge with ``charset=UTF-8`` is reported as
  UTF-8.  Any other charset is accepted by the parser but surfaced as the
  raw token so the caller can decide.  On the authorization side the
  credentials are decoded as UTF-8 when possible and otherwise as
  ISO-8859-1, matching how the bytes were most likely produced.
* All header names are matched case-insensitively, but the returned objects
  only expose the credentials and the charset; the caller already knows
  which header it asked about.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "BasicAuthError",
    "InvalidAuthorizationHeader",
    "InvalidChallengeHeader",
    "BasicCredentials",
    "BasicChallenge",
    "parse_authorization",
    "build_authorization",
    "parse_challenge",
    "build_challenge",
]


class BasicAuthError(ValueError):
    """Base class for all errors raised by this module."""


class InvalidAuthorizationHeader(BasicAuthError):
    """Raised when an ``Authorization`` header cannot be parsed."""


class InvalidChallengeHeader(BasicAuthError):
    """Raised when a ``WWW-Authenticate`` header cannot be parsed."""


@dataclass(frozen=True)
class BasicCredentials:
    """Credentials extracted from an ``Authorization: Basic`` header.

    ``username`` and ``password`` are ``str`` instances.  The bytes on the
    wire were decoded as UTF-8 when that succeeded, otherwise as
    ISO-8859-1; both mappings are total, so no decoding error escapes.
    """

    username: str
    password: str


@dataclass(frozen=True)
class BasicChallenge:
    """A parsed ``WWW-Authenticate: Basic`` challenge.

    ``realm`` is ``None`` when the challenge omitted it.  ``charset`` is
    ``None`` when the challenge omitted the parameter, ``"UTF-8"`` when it
    was present as UTF-8 (case-insensitively), and otherwise the raw token
    as sent by the server.
    """

    realm: Optional[str]
    charset: Optional[str]


_WS_RE = re.compile(r"[ \t\r\n]+")
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _decode_base64_loose(payload: str) -> bytes:
    """Decode base64 ignoring ASCII whitespace.

    RFC 2045 allows line breaks inside base64, and some clients emit them.
    ``base64.b64decode`` with ``validate=False`` already ignores characters
    outside the alphabet, but it does not ignore whitespace in the middle of
    a quantum, so we strip it explicitly first.
    """
    compact = _WS_RE.sub("", payload)
    if not compact:
        raise InvalidAuthorizationHeader("empty base64 payload")
    # Pad to a multiple of four; some clients omit trailing '='.
    pad = (-len(compact)) % 4
    if pad == 3:
        # A single leftover character cannot be valid base64.
        raise InvalidAuthorizationHeader("invalid base64 payload length")
    if pad:
        compact += "=" * pad
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidAuthorizationHeader("invalid base64 payload") from exc


def _split_scheme(header: str, error: type) -> Tuple[str, str]:
    """Split ``header`` into ``(scheme, rest)`` or raise ``error``."""
    if not isinstance(header, str):
        raise error("header must be a string")
    stripped = header.strip()
    if not stripped:
        raise error("empty header")
    parts = stripped.split(None, 1)
    if len(parts) == 1:
        scheme, rest = parts[0], ""
    else:
        scheme, rest = parts
    if scheme.lower() != "basic":
        raise error("unsupported scheme: %s" % scheme)
    return scheme, rest


def _split_credentials(raw: bytes) -> BasicCredentials:
    """Split decoded bytes on the first colon.

    RFC 7617 says the user-id must not contain a colon, so the first colon
    is the separator.  A missing colon is an error rather than an empty
    password, because silently accepting it hides malformed clients.
    """
    colon = raw.find(b":")
    if colon < 0:
        raise InvalidAuthorizationHeader("credentials missing ':' separator")
    user_bytes = raw[:colon]
    pass_bytes = raw[colon + 1 :]
    try:
        user = user_bytes.decode("utf-8")
        password = pass_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # Fall back to the historical ISO-8859-1 mapping; it is total.
        user = user_bytes.decode("latin-1")
        password = pass_bytes.decode("latin-1")
    return BasicCredentials(username=user, password=password)


def parse_authorization(header: str) -> BasicCredentials:
    """Parse an ``Authorization: Basic`` header value.

    ``header`` is the full field value, e.g. ``"Basic dXNlcjpwYXNz"``.
    Raises :class:`InvalidAuthorizationHeader` on any malformed input.
    """
    _, rest = _split_scheme(header, InvalidAuthorizationHeader)
    if not rest:
        raise InvalidAuthorizationHeader("missing credentials after scheme")
    raw = _decode_base64_loose(rest)
    return _split_credentials(raw)


def build_authorization(username: str, password: str, charset: str = "utf-8") -> str:
    """Build an ``Authorization: Basic`` header value.

    ``charset`` selects the encoding used for the user-id and password
    before base64.  The default is UTF-8, which is what modern clients use.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("username and password must be strings")
    if ":" in username:
        raise ValueError("username must not contain ':'")
    try:
        raw = (username + ":" + password).encode(charset)
    except LookupError as exc:
        raise ValueError("unknown charset: %s" % charset) from exc
    except UnicodeEncodeError as exc:
        raise ValueError("credentials cannot be encoded as %s" % charset) from exc
    token = base64.b64encode(raw).decode("ascii")
    return "Basic " + token


def _parse_auth_params(rest: str) -> dict:
    """Parse ``key=value`` parameters from a challenge.

    The grammar is intentionally narrow: tokens separated by commas, values
    either tokens or quoted strings.  This covers every Basic challenge seen
    in practice and avoids a full RFC 7235 parser, which would be a much
    larger surface than this library needs.
    """
    params = {}
    i = 0
    n = len(rest)
    while i < n:
        while i < n and rest[i] in " \t,":
            i += 1
        if i >= n:
            break
        start = i
        while i < n and rest[i] not in "=,":
            i += 1
        key = rest[start:i].strip()
        if not key:
            raise InvalidChallengeHeader("empty parameter name")
        if i >= n or rest[i] != "=":
            raise InvalidChallengeHeader("parameter %r missing '='" % key)
        i += 1
        while i < n and rest[i] in " \t":
            i += 1
        if i < n and rest[i] == '"':
            i += 1
            chars = []
            while i < n and rest[i] != '"':
                if rest[i] == "\\" and i + 1 < n:
                    chars.append(rest[i + 1])
                    i += 2
                else:
                    chars.append(rest[i])
                    i += 1
            if i >= n:
                raise InvalidChallengeHeader("unterminated quoted string")
            i += 1  # consume closing quote
            value = "".join(chars)
        else:
            start = i
            while i < n and rest[i] != ",":
                i += 1
            value = rest[start:i].strip()
        params[key.lower()] = value
    return params


def parse_challenge(header: str) -> BasicChallenge:
    """Parse a ``WWW-Authenticate: Basic`` challenge value.

    ``header`` is the full field value, e.g.
    ``'Basic realm="example", charset="UTF-8"'``.  Raises
    :class:`InvalidChallengeHeader` on malformed input.
    """
    _, rest = _split_scheme(header, InvalidChallengeHeader)
    params = _parse_auth_params(rest)
    realm = params.get("realm")
    charset = params.get("charset")
    if charset is not None and charset.lower() == "utf-8":
        charset = "UTF-8"
    return BasicChallenge(realm=realm, charset=charset)


def _quote(value: str) -> str:
    """Quote a parameter value per RFC 7235 ``quoted-string`` rules."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_challenge(realm: Optional[str] = None, charset: Optional[str] = None) -> str:
    """Build a ``WWW-Authenticate: Basic`` challenge value.

    ``realm`` and ``charset`` are omitted when ``None``.  ``charset`` is
    emitted verbatim; callers that want UTF-8 should pass ``"UTF-8"``.
    """
    parts = []
    if realm is not None:
        parts.append("realm=" + _quote(realm))
    if charset is not None:
        parts.append("charset=" + _quote(charset))
    if not parts:
        return "Basic"
    return "Basic " + ", ".join(parts)
