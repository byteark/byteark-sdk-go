# Migrating from v1 to v2

v1 (`github.com/byteark/byteark-sdk-go`, tags `v0.1.x`) keeps one process-wide signer configured
through `CreateSigner` / `CurrentSigner().Set*`. v2 (`github.com/byteark/byteark-sdk-go/v2`)
replaces it with an immutable `*Signer` per credential that you construct once and pass around.
v1 stays available at its tags; this repository now carries v2 only.

## Fastest path: the agent skill
Copy `skills/byteark-signer-migrate-v2/` into your repo's skills directory and ask your coding
agent to migrate the repo to ByteArk signer v2. The skill carries the search checklist, the
before/after transforms and the completion criteria.

## What changes

| v1 | v2 |
|---|---|
| `CreateSigner(SignerOptions{AccessID, AccessSecret, DefaultAge})` | `New(id, secret, WithDefaultAge(d))` |
| `CurrentSigner().SetAccessID(...)` and the other setters | construct a new `Signer`; there are no setters |
| `Sign(url, expires int, SignOptions{...})` | `signer.Sign(url, time.Unix(expires, 0), PathPrefix(...), ClientIP(...), ...)` |
| `SignOptions` map with string keys | typed conditions; `Custom(key, value)` for any other policy key |
| `Verify(url, now int) (bool, error)` | `signer.Verify(url, time.Unix(now, 0), conds...) error`; read the cause with `errors.Is` against the `Err*` sentinels |
| strip `x_ark_*` by hand, then `Sign` again | `signer.Renew(signedURL, expires)` to refresh only the expiry; `signer.Reissue(signedURL, expires, conds...)` to change the policy |
| unsupported HTTP methods accepted as given | any method accepted and upper-cased before signing |
| path line of the string-to-sign percent-decoded | path signed **as written**, percent-escapes intact (see below) |
| URL that already has a query silently mis-signed | `ErrURLHasQuery`; `Reissue` accepts such URLs |

The host line (`host:port`, as written) is unchanged from v1.

## Query encoding: unchanged
v1 always form-encoded query values (`x_ark_path_prefix=%2Flive%2F`); its `SkipURLEncoding`
setting had no effect on the output. v2's default produces the same bytes, so a migrated call
site emits byte-identical URLs. `WithSkipURLEncoding(true)` is a different wire form that v1
never produced.

## Signature-affecting differences
Two changes alter `x_ark_signature` itself. They only matter for the URL shapes named below;
everything else signs identically to v1. If any of your URLs hit these cases, sign one with v2
and confirm the CDN accepts it before switching over.

- **Path is signed exactly as written.** v1 signs the percent-decoded path; v2 signs the path
  as it appears in the URL, leaving percent-escapes intact. For
  `http://inox.qoder.byteark.com/video%20objects/x/playlist.m3u8` v2 signs the literal
  `/video%20objects/x/playlist.m3u8` and yields `x_ark_signature=0HZGLFsiERiOdGV_J28yQg`,
  whereas v1 signs the decoded `/video objects/x/playlist.m3u8` and therefore produces a
  different signature. Paths that contain no percent-escapes are unaffected.

- **Method is upper-cased.** v1 signs the method string exactly as you pass it; v2 upper-cases
  it (`put` becomes `PUT`). If you passed a lower-case method to v1, its signature differs from
  v2's. An already upper-case method, or an omitted one (default `GET`), is unaffected.

## Before / after
```go
// v1
bytearkSignedURL.CreateSigner(bytearkSignedURL.SignerOptions{AccessID: id, AccessSecret: secret})
signed, err := bytearkSignedURL.Sign(url, 1514764800, bytearkSignedURL.SignOptions{"path_prefix": "/live/"})
ok, err := bytearkSignedURL.Verify(signed, int(time.Now().Unix()))

// v2
signer, err := bytearksigner.New(id, secret)
signed, err := signer.Sign(url, time.Unix(1514764800, 0), bytearksigner.PathPrefix("/live/"))
err = signer.Verify(signed, time.Now())
```
