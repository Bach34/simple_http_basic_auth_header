"""Public interface for simple_http_basic_auth_header.

Exports the small set of functions and exception types needed to parse and
construct HTTP Basic Authorization and WWW-Authenticate headers.
"""

from .core import (
    BasicAuthError,
    InvalidAuthorizationHeader,
    InvalidChallengeHeader,
    BasicCredentials,
    BasicChallenge,
    parse_authorization,
    build_authorization,
    parse_challenge,
    build_challenge,
)

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
