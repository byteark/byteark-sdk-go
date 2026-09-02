# v1 remnant search checklist

Run all of these from the module root; migration is complete only when every one prints nothing.

```bash
# 1. Any v1 import path (aliased or not), excluding /v2
grep -rnE '"github.com/byteark/byteark-sdk-go"' --include='*.go' .
# 2. go.mod requirement
grep -nE 'github.com/byteark/byteark-sdk-go( |$)' go.mod
# 3. Global constructor / accessor
grep -rnE '\b(CreateSigner|CurrentSigner)\(' --include='*.go' .
# 4. Mutable setters on the global signer
grep -rnE '\.Set(AccessID|AccessSecret|DefaultAge|SkipURLEncoding)\(' --include='*.go' .
# 5. v1 option map type
grep -rnE '\bSignOptions\b' --include='*.go' .
# 6. Package-level Sign/Verify through any alias. First list the aliases used for the v1 import:
grep -rhoE '^\s*[A-Za-z_][A-Za-z0-9_]* "github.com/byteark/byteark-sdk-go"' --include='*.go' . | awk '{print $1}' | sort -u
#    then, for each alias printed (none printed = this check is already clean), run:
#    grep -rnE '\b<alias>\.(Sign|Verify)\(' --include='*.go' .
# 7. Newly introduced globals holding a signer (must be none)
grep -rnE '^var .*\*?bytearksigner\.Signer' --include='*.go' .
```
