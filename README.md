# simple_http_basic_auth_header

Parse and build HTTP Basic `Authorization` and `WWW-Authenticate` headers,
including the RFC 7617 `charset` parameter and RFC 2045 base64 with whitespace
tolerance.

```python
from simple_http_basic_auth_header import (
    parse_authorization,
    build_authorization,
    parse_challenge,
    build_challenge,
)

header = build_authorization("alice", "s3cret")
# 'Basic YWxpY2U6czNjcmV0'
creds = parse_authorization(header)
# BasicCredentials(username='alice', password='s3cret')

challenge = parse_challenge('Basic realm="example", charset="UTF-8"')
# BasicChallenge(realm='example', charset='UTF-8')
header = build_challenge(realm="example", charset="UTF-8")
# 'Basic realm="example", charset="UTF-8"'
```

The module exports `BasicAuthError`, `InvalidAuthorizationHeader`,
`InvalidChallengeHeader`, `BasicCredentials`, `BasicChallenge`,
`parse_authorization`, `build_authorization`, `parse_challenge`, and
`build_challenge`.

## Why this exists

Basic auth looks like one line of base64, but the bytes on the wire are not
uniform. Proxies fold the base64 payload across lines; some clients omit
trailing `=` padding; the `charset` parameter is only defined on the
challenge and only for UTF-8; and the user-id is not allowed to contain a
colon, so the first colon is always the separator. Doing this with ad-hoc
`split(" ")` and `b64decode` in every service reproduces the same bugs.

The trade-off here is strictness on the structural side and leniency on the
encoding side. The scheme must be `Basic`, a missing colon in the decoded
credentials is an error, and a malformed challenge parameter is an error —
but whitespace inside the base64 payload is stripped, missing padding is
re-added, and credentials that are not valid UTF-8 fall back to ISO-8859-1
rather than failing. That matches what a server actually sees in practice
while still refusing input that cannot be interpreted.

## The awkward edge

`parse_challenge` accepts any `charset` token and returns it verbatim
except for `UTF-8`, which is normalised to upper case. It does not reject
unknown charsets, because the server may be advertising something the
client simply does not implement, and the caller is better placed to decide
whether to proceed. `parse_authorization` has no charset parameter to read,
so it tries UTF-8 first and falls back to ISO-8859-1; that fallback is
total, so it never raises a decoding error. If you need to know which
encoding was actually used, encode explicitly with `build_authorization`
and keep track of the charset out of band.
