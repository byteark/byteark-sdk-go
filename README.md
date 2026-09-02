# ByteArk Signer SDK for Go

Instance-based signer and verifier for ByteArk signed URLs (`ark-v2`). A `Signer` is
immutable after `New` and safe for concurrent use, so one signer per credential pair
can be shared freely.

Requires **Go 1.24** or newer.

    go get github.com/byteark/byteark-sdk-go/v2

```go
import (
    "errors"
    "time"

    bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

signer, err := bytearksigner.New("ACCESS_ID", "ACCESS_SECRET")
if err != nil {
    return err
}

signedURL, err := signer.Sign(
    "https://example.cdn.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
    time.Now().Add(15*time.Minute),
    bytearksigner.PathPrefix("/video-objects/QDuxJm02TYqJ/"),
)
if err != nil {
    return err
}

// Verifying on your own backend:
switch err := signer.Verify(signedURL, time.Now()); {
case err == nil:
    // valid
case errors.Is(err, bytearksigner.ErrExpired):
    // lapsed
case errors.Is(err, bytearksigner.ErrPathPrefix),
    errors.Is(err, bytearksigner.ErrSignature),
    errors.Is(err, bytearksigner.ErrMalformed):
    // reject
}
```

## API

| Symbol | Notes |
|---|---|
| `New(accessID, accessSecret string, opts ...Option) (*Signer, error)` | `accessSecret` is required; `accessID` may be empty |
| `WithDefaultAge(d time.Duration) Option` | lifetime used when `Sign` gets a zero `expires` (default `DefaultAge` = 900s); must be positive |
| `WithSkipURLEncoding(skip bool) Option` | `false` (default) URL-encodes query values; `true` emits them raw |
| `WithHasher(newHash func() hash.Hash) Option` | replaces the default MD5; only useful if your verifier is configured to match |
| `(*Signer).Sign(rawURL string, expires time.Time, conds ...Condition) (string, error)` | `rawURL` must not already carry a query string (`ErrURLHasQuery`) |
| `(*Signer).Verify(signedURL string, at time.Time, conds ...Condition) error` | `nil` means valid |
| `(*Signer).Renew(signedURL string, expires time.Time, conds ...Condition) (string, error)` | new expiry and signature, same policy |
| `(*Signer).Reissue(rawURL string, expires time.Time, conds ...Condition) (string, error)` | re-sign with a changed policy and this signer's credentials |

Conditions:

| Condition | Effect |
|---|---|
| `PathPrefix(prefix string)` | signature covers every URL under `prefix` instead of the single path |
| `ClientIP(ip string)` | restricts to one client IP; signed, but masked as `x_ark_client_ip=1` on the wire |
| `UserAgent(ua string)` | restricts to one `User-Agent`; signed, but masked as `x_ark_user_agent=1` |
| `Method(method string)` | restricts to one HTTP method (default `GET`); upper-cased, never appears in the URL |
| `Custom(key, value string)` | arbitrary policy option; `key` is canonicalised (lower-cased, with `-` replaced by `_`) and emitted as `x_ark_<key>`; an empty value is ignored |
| `Without(key string)` | removes a policy option; meaningful in `Reissue`, rejected by `Renew` with `ErrPolicyChange` |

Errors (all sentinels, matched with `errors.Is`):

`ErrMissingSecret`, `ErrURLHasQuery`, `ErrMalformed`, `ErrExpired`, `ErrPathPrefix`,
`ErrSignature`, `ErrNotSigned`, `ErrMaskedValue`, `ErrPolicyChange`.

### Masked conditions and Verify

`ClientIP` and `UserAgent` are part of the signature but reach the client as `=1`, and
`Method` never appears in the URL at all. None of the three is recoverable from a signed
URL, so `Verify` needs the actual request values passed back as conditions; they override
whatever the wire carried.

```go
err := signer.Verify(signedURL, time.Now(),
    bytearksigner.ClientIP(r.RemoteAddr),
    bytearksigner.UserAgent(r.UserAgent()),
    bytearksigner.Method(r.Method),
)
```

### Renew vs Reissue

`Renew` is the strict path. It requires a complete `ark-v2` envelope
(`x_ark_auth_type`, `x_ark_expires`, `x_ark_signature`, `x_ark_access_id`) and refuses to
proceed unless the **existing signature verifies with this signer's access secret**
(whether it has already lapsed is not checked — extending an expired URL is what `Renew`
is for). It then replaces the values of `x_ark_expires` and `x_ark_signature` in place, so
every other parameter keeps its original spelling, encoding and position, and the fragment
is preserved. The policy may not change: conditions may only supply what the wire cannot
carry (`ClientIP`/`UserAgent` for keys already masked as `1`, and `Method`); anything else
is rejected with `ErrPolicyChange`. `x_ark_access_id` is passed through untouched.

`Reissue` is the permissive path. It **discards the input's envelope without ever checking
the old signature**, takes the remaining `x_ark_*` parameters as a base policy, applies the
conditions on top, and signs afresh with this signer's credentials — so it is also the
key-rotation path and the only way to sign a URL that already has a query string. Because
it trusts the URL it is given, use `Reissue` only on input you trust.

## Wire format

- The query string is form-encoded by default: a space becomes `+`, `~` becomes `%7E`
  (e.g. a path prefix of `/a b~c/ü/` is emitted as `x_ark_path_prefix=%2Fa+b%7Ec%2F%C3%BC%2F`).
  `WithSkipURLEncoding(true)` emits the raw value instead; the signature is unaffected.
- The host line of the signed string includes an explicit port whenever the URL has one
  (`inox.qoder.byteark.com:8080`, not just the hostname), so a URL with a port and the same
  URL without one produce different signatures.
- The path is signed exactly as written, with percent-encoding preserved: `/video%20objects/…`
  is signed in that escaped form, not decoded first.

`testdata/reference_vectors.json` holds the frozen reference vectors that every signer in
this module must reproduce; `go test ./...` checks each one.

## License

Apache License 2.0. See [LICENSE](LICENSE).
