package bytearksigner

import (
	"fmt"
	"strings"
)

// maskedValue is what the wire carries in place of a masked condition's real
// value (x_ark_client_ip, x_ark_user_agent).
const maskedValue = "1"

// Condition constrains a signed URL: which path prefix, client IP, user agent,
// or HTTP method it is valid for, or any arbitrary x_ark_* policy option.
type Condition func(policy)

// policy is the canonicalised option set for one Sign/Verify call.
// Canonical key form: lower-case, '-' replaced by '_'.
type policy map[string]string

func newPolicy(conds []Condition) policy {
	p := make(policy, len(conds))
	for _, c := range conds {
		if c != nil {
			c(p)
		}
	}
	return p
}

func canonicalKey(key string) string {
	return strings.ReplaceAll(strings.ToLower(key), "-", "_")
}

// Custom sets an arbitrary policy option; key is canonicalised (lowercase,
// '-' replaced by '_') and emitted as x_ark_<key>. Empty values are ignored.
// Prefer the typed helpers for the first-class conditions.
func Custom(key, value string) Condition {
	return func(p policy) {
		if value == "" {
			return
		}
		p[canonicalKey(key)] = value
	}
}

// PathPrefix restricts the signature to every URL under prefix instead of a single path.
func PathPrefix(prefix string) Condition { return Custom("path_prefix", prefix) }

// ClientIP restricts the signed URL to one client IP. The IP is part of the
// signature but is masked as x_ark_client_ip=1 in the URL.
func ClientIP(ip string) Condition { return Custom("client_ip", ip) }

// UserAgent restricts the signed URL to one User-Agent header value. Masked as
// x_ark_user_agent=1 in the URL.
func UserAgent(ua string) Condition { return Custom("user_agent", ua) }

// Method restricts the signed URL to one HTTP method (default GET). The value
// is upper-cased and does not appear in the URL.
func Method(method string) Condition { return Custom("method", strings.ToUpper(method)) }

// Without removes a policy option instead of setting one; key is canonicalised
// the same way Custom canonicalises it, and removing an option that is not
// present does nothing.
//
// It is meaningful in Reissue, whose base policy comes from the x_ark_*
// parameters already on the URL, and is how a policy option is dropped rather
// than overridden. On Sign it is harmless but pointless, since that policy is
// built from the conditions themselves; Renew rejects it with ErrPolicyChange
// whenever it would actually remove something, because Renew may not change the
// policy at all.
func Without(key string) Condition {
	return func(p policy) { delete(p, canonicalKey(key)) }
}

func (p policy) method() string {
	if m, ok := p["method"]; ok && m != "" {
		// The signed method line is upper-case unconditionally, so a method
		// arriving through Custom (value unmodified) is upper-cased here.
		return strings.ToUpper(m)
	}
	return "GET"
}

func (p policy) clone() policy {
	c := make(policy, len(p))
	for k, v := range p {
		c[k] = v
	}
	return c
}

// checkMaskedResolved reports whether any masked option still carries the wire
// placeholder instead of the real value. Signing one would produce a URL that
// can never verify, so both Renew and Reissue refuse it.
func (p policy) checkMaskedResolved() error {
	for _, k := range []string{"client_ip", "user_agent"} {
		if p[k] == maskedValue {
			return fmt.Errorf("%w: %s is %q on the wire; pass the real value", ErrMaskedValue, k, maskedValue)
		}
	}
	return nil
}

func (p policy) pathPrefix() (string, bool) {
	v, ok := p["path_prefix"]
	return v, ok && v != ""
}
