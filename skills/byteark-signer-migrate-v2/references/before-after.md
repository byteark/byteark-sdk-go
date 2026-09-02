# Before / after transforms

## Startup / configuration
```go
// before (v1)
import bytearkSignedURL "github.com/byteark/byteark-sdk-go"

if err := bytearkSignedURL.CreateSigner(bytearkSignedURL.SignerOptions{
    AccessID:     cfg.AccessID,
    AccessSecret: cfg.AccessSecret,
    DefaultAge:   600,
}); err != nil {
    return err
}
```
```go
// after (v2)
import bytearksigner "github.com/byteark/byteark-sdk-go/v2"

signer, err := bytearksigner.New(cfg.AccessID, cfg.AccessSecret,
    bytearksigner.WithDefaultAge(600*time.Second),
)
if err != nil {
    return err
}
app.signer = signer // pass it to whoever signs
```

## Setter chain
```go
// before
s := bytearkSignedURL.CurrentSigner()
s.SetAccessID(id); s.SetAccessSecret(secret); s.SetSkipURLEncoding(false)
```
```go
// after
signer, err := bytearksigner.New(id, secret) // encoding on is the default, as it effectively was in v1
```

## Sign with options
Option keys map to conditions: `path_prefix` becomes `PathPrefix`; `client_ip` or `client-ip` becomes `ClientIP`;
`user_agent` becomes `UserAgent`; `method` becomes `Method`; any other key becomes `Custom(key, value)`.
```go
// before
signed, err := bytearkSignedURL.Sign(rawURL, 1514764800, bytearkSignedURL.SignOptions{
    "path_prefix": "/live/",
    "client-ip":   clientIP,
    "method":      "POST",
    "viewer_group": "vip",
})
```
```go
// after
signed, err := app.signer.Sign(rawURL, time.Unix(1514764800, 0),
    bytearksigner.PathPrefix("/live/"),
    bytearksigner.ClientIP(clientIP),
    bytearksigner.Method("POST"),
    bytearksigner.Custom("viewer_group", "vip"),
)
```

## Sign with default age
```go
// before
signed, err := bytearkSignedURL.Sign(rawURL, 0, nil)
```
```go
// after
signed, err := app.signer.Sign(rawURL, time.Time{})
```

## Verify
v1 returned `(ok bool, err error)`; v2 returns one error, `nil` when valid, and the cause is
read with `errors.Is` against the sentinels.
```go
// before
ok, err := bytearkSignedURL.Verify(signedURL, int(time.Now().Unix()))
if err != nil || !ok { return http.StatusForbidden }
```
```go
// after
err := app.signer.Verify(signedURL, time.Now(),
    bytearksigner.ClientIP(realClientIP), // only if the URL was signed with ClientIP
)
switch {
case err == nil:
case errors.Is(err, bytearksigner.ErrExpired): return http.StatusGone
default: return http.StatusForbidden
}
```

## Re-signing an existing signed URL
```go
// before: strip x_ark_* by hand, then sign the bare URL again
bare, conds := stripArkParams(signedURL)
renewed, err := bytearkSignedURL.Sign(bare, newExpiry, conds)
```
```go
// after: same conditions, new expiry — verifies the existing signature first
renewed, err := app.signer.Renew(signedURL, time.Unix(newExpiry, 0))

// after: changed conditions (trusted input only — the old signature is not checked)
reissued, err := app.signer.Reissue(signedURL, time.Unix(newExpiry, 0),
    bytearksigner.PathPrefix("/live/2026/"),
    bytearksigner.Without("viewer_group"),
)
```

## Wire differences vs v1

Two shapes sign a different `x_ark_signature` under v2; verify a signed sample of each against
the CDN before switching. Everything else, query encoding included, is byte-identical.

| # | Aspect | v1 (github.com/byteark/byteark-sdk-go) | v2 | Effect on `x_ark_signature` |
|---|--------|----------------------------------------|----|-----------------------------|
| a | Query value encoding | always form-encoded (the `SkipURLEncoding` setting had no effect on output) | form-encoded by default | None — byte-identical URLs. |
| b | Path in the signature | signs the **decoded** path | signs the path **as written** (percent-escapes kept) | Changes for paths containing percent-escapes such as `%20` or `%2F`; identical for plain paths. |
| c | HTTP method | method case used **as given** | method **upper-cased** before signing (`get` becomes `GET`) | Changes for a lower- or mixed-case `method`; identical for `GET` or an already upper-case method. |
| d | URL already has a query | silently produced a broken URL | returns `ErrURLHasQuery` | N/A — `Sign` now errors; strip the query first or use `Reissue`. |

v2 hashes with MD5 like v1; `WithHasher` is for a CDN configured to verify another hash.
