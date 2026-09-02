---
name: byteark-signer-migrate-v2
description: Migrate Go code from ByteArk signer v1 (github.com/byteark/byteark-sdk-go, one process-wide signer) to v2 (github.com/byteark/byteark-sdk-go/v2, one Signer per credential). Use when a module imports or requires github.com/byteark/byteark-sdk-go without the /v2 suffix.
---

# Migrate ByteArk signer v1 to v2

Install by copying this directory into the target repo's skills folder (for example `.claude/skills/byteark-signer-migrate-v2/`).

## Workflow — sweep until the checklist is clean

1. **Inventory.** Run every search in `references/search-checklist.md` from the module root. Each hit is one call site to migrate.
2. **Home the Signer.** v2 replaces the process-wide signer with one `*bytearksigner.Signer` per credential. Build it with `bytearksigner.New(...)` where the v1 `CreateSigner` or `CurrentSigner().Set*` chain ran (startup or config), store it on the type that owns the configuration, and pass it to every call site. With no owning type (a flat `package main`, free helpers), thread it: the setup helper returns the `*Signer`, every signing helper takes it as its first parameter, and their callers and tests change in the same pass. The checklist's last search proves the Signer lives nowhere else.
3. **Rewrite call sites** with the transforms in `references/before-after.md`: startup, setter chain, sign with options, sign with default age, verify, and hand-rolled re-signing (which becomes `Renew` or `Reissue`).
4. **Keep the default encoding.** v1 always form-encoded query values (its `SkipURLEncoding` setting had no effect on output), and v2's default produces the same bytes. The only Signer option a migration adds is `WithDefaultAge`; `WithHasher` only when the CDN verifies a hash other than MD5.
5. **Update go.mod.** v2 needs Go 1.24 or newer. Published v2: `go get github.com/byteark/byteark-sdk-go/v2@latest && go mod tidy`. Local checkout: `go mod edit -require=github.com/byteark/byteark-sdk-go/v2@v2.0.0 -replace=github.com/byteark/byteark-sdk-go/v2=<path> && go mod tidy`. Once no v1 import remains, `go mod tidy` drops the v1 requirement; a v1 `replace` goes with `go mod edit -dropreplace=github.com/byteark/byteark-sdk-go`.
6. **Verify.** `go build ./... && go vet ./... && go test ./...` green, and every fixture that holds a signed URL is byte-identical to before. The two permitted exceptions are the wire differences table in `references/before-after.md` (percent-escapes in the path, a method not already upper-case); any other change is a defect to find before shipping.
7. **Sweep again.** Rerun step 1. Done when every search prints nothing and step 6 holds.

## Pitfalls
- Aliased imports (`bytearkSignedURL "github.com/byteark/byteark-sdk-go"`) hide the package name; search by import path, as the checklist does.
- A wrapper such as `func SignURL(u string) string` around the global `Sign` gains a `*Signer` receiver or parameter.
- v1 took `expires int` and treated every non-zero value as an absolute Unix timestamp, so `time.Unix(int64(expires), 0)` preserves behaviour; make the unit explicit at the call site.
- `Verify` takes the real request values for the masked conditions `ClientIP` and `UserAgent` (the URL carries only `1` for them), and only for URLs signed with those conditions.
- `Sign` returns `ErrURLHasQuery` for a URL that already carries `?…`, where v1 produced a broken URL silently: strip the query first, or use `Reissue`, which accepts parameters already on the URL.
- `x_ark_origin` is matched by the CDN edge as the literal `1`; keep whatever value the v1 code passed, since a URL value there signs something the edge will not match, in v1 and v2 alike.
