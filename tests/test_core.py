"""Tests for simple_http_basic_auth_header.core.

These tests exercise the behaviour the module actually claims: loose base64
whitespace, UTF-8 with ISO-8859-1 fallback, case-insensitive scheme and
parameter names, and strict errors for malformed input.
"""

import base64
import unittest

from simple_http_basic_auth_header import (
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


class ParseAuthorizationTests(unittest.TestCase):
    def test_round_trip_ascii(self):
        header = build_authorization("alice", "secret")
        self.assertEqual(header, "Basic YWxpY2U6c2VjcmV0")
        creds = parse_authorization(header)
        self.assertEqual(creds, BasicCredentials("alice", "secret"))

    def test_scheme_is_case_insensitive(self):
        token = base64.b64encode(b"bob:hunter2").decode("ascii")
        creds = parse_authorization("basic " + token)
        self.assertEqual(creds, BasicCredentials("bob", "hunter2"))

    def test_whitespace_inside_base64_is_ignored(self):
        token = base64.b64encode(b"carol:pw").decode("ascii")
        folded = token[:4] + "\r\n " + token[4:]
        creds = parse_authorization("Basic " + folded)
        self.assertEqual(creds, BasicCredentials("carol", "pw"))

    def test_missing_padding_is_accepted(self):
        # "user:pw" is 7 bytes, so base64 has one '=' of padding.
        token = base64.b64encode(b"user:pw").decode("ascii").rstrip("=")
        creds = parse_authorization("Basic " + token)
        self.assertEqual(creds, BasicCredentials("user", "pw"))

    def test_utf8_credentials(self):
        header = build_authorization("\u00e9lise", "p\u00e4ss")
        creds = parse_authorization(header)
        self.assertEqual(creds, BasicCredentials("\u00e9lise", "p\u00e4ss"))

    def test_iso_8859_1_fallback(self):
        raw = b"caf\xe9:pw"
        token = base64.b64encode(raw).decode("ascii")
        creds = parse_authorization("Basic " + token)
        self.assertEqual(creds, BasicCredentials("caf\xe9", "pw"))

    def test_empty_password_is_allowed(self):
        token = base64.b64encode(b"user:").decode("ascii")
        creds = parse_authorization("Basic " + token)
        self.assertEqual(creds, BasicCredentials("user", ""))

    def test_missing_colon_is_rejected(self):
        token = base64.b64encode(b"nocolon").decode("ascii")
        with self.assertRaises(InvalidAuthorizationHeader):
            parse_authorization("Basic " + token)

    def test_wrong_scheme_is_rejected(self):
        with self.assertRaises(InvalidAuthorizationHeader):
            parse_authorization("Bearer abc")

    def test_empty_header_is_rejected(self):
        with self.assertRaises(InvalidAuthorizationHeader):
            parse_authorization("   ")

    def test_invalid_base64_is_rejected(self):
        with self.assertRaises(InvalidAuthorizationHeader):
            parse_authorization("Basic !!!!")

    def test_build_rejects_colon_in_username(self):
        with self.assertRaises(ValueError):
            build_authorization("a:b", "pw")

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(InvalidAuthorizationHeader, BasicAuthError))
        self.assertTrue(issubclass(InvalidChallengeHeader, BasicAuthError))


class ParseChallengeTests(unittest.TestCase):
    def test_realm_and_charset(self):
        challenge = parse_challenge('Basic realm="example", charset="UTF-8"')
        self.assertEqual(challenge, BasicChallenge("example", "UTF-8"))

    def test_realm_only(self):
        challenge = parse_challenge('Basic realm="example"')
        self.assertEqual(challenge, BasicChallenge("example", None))

    def test_charset_only(self):
        challenge = parse_challenge('Basic charset="UTF-8"')
        self.assertEqual(challenge, BasicChallenge(None, "UTF-8"))

    def test_charset_case_insensitive(self):
        challenge = parse_challenge('Basic realm="r", charset="utf-8"')
        self.assertEqual(challenge.charset, "UTF-8")

    def test_unknown_charset_is_preserved(self):
        challenge = parse_challenge('Basic realm="r", charset="ISO-8859-1"')
        self.assertEqual(challenge.charset, "ISO-8859-1")

    def test_unquoted_realm_token(self):
        challenge = parse_challenge("Basic realm=example")
        self.assertEqual(challenge.realm, "example")

    def test_quoted_string_with_escaped_quote(self):
        challenge = parse_challenge('Basic realm="a\\"b"')
        self.assertEqual(challenge.realm, 'a"b')

    def test_missing_realm_is_none(self):
        challenge = parse_challenge("Basic")
        self.assertEqual(challenge, BasicChallenge(None, None))

    def test_wrong_scheme_is_rejected(self):
        with self.assertRaises(InvalidChallengeHeader):
            parse_challenge('Digest realm="example"')

    def test_missing_equals_is_rejected(self):
        with self.assertRaises(InvalidChallengeHeader):
            parse_challenge("Basic realm")

    def test_unterminated_quote_is_rejected(self):
        with self.assertRaises(InvalidChallengeHeader):
            parse_challenge('Basic realm="unterminated')


class BuildChallengeTests(unittest.TestCase):
    def test_empty_challenge(self):
        self.assertEqual(build_challenge(), "Basic")

    def test_realm_only(self):
        self.assertEqual(build_challenge(realm="example"), 'Basic realm="example"')

    def test_realm_and_charset(self):
        self.assertEqual(
            build_challenge(realm="example", charset="UTF-8"),
            'Basic realm="example", charset="UTF-8"',
        )

    def test_quotes_are_escaped(self):
        self.assertEqual(
            build_challenge(realm='a"b'),
            'Basic realm="a\\"b"',
        )

    def test_round_trip(self):
        header = build_challenge(realm='a"b', charset="UTF-8")
        challenge = parse_challenge(header)
        self.assertEqual(challenge, BasicChallenge('a"b', "UTF-8"))


if __name__ == "__main__":
    unittest.main()
