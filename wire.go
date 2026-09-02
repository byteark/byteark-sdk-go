package bytearksigner

import (
	"encoding/base64"
	"hash"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const authType = "ark-v2"

// isEnvelopeKey reports whether k is one of the four envelope query keys
// carried on every signed URL; these are never part of the policy lines.
func isEnvelopeKey(k string) bool {
	switch k {
	case "x_ark_access_id", "x_ark_auth_type", "x_ark_expires", "x_ark_signature":
		return true
	default:
		return false
	}
}

// stringToSign builds the ark-v2 plaintext:
//
//	METHOD \n host \n (path_prefix|path) \n key:value… (sorted) \n expires \n secret
func stringToSign(u *url.URL, expires int64, p policy, secret string) string {
	lines := make([]string, 0, 5+len(p))
	// host:port, exactly as written (matches the JS SDK and the CDN verifier).
	lines = append(lines, p.method(), u.Host)
	if prefix, ok := p.pathPrefix(); ok {
		lines = append(lines, prefix)
	} else {
		// The path is signed as written, percent-encoding preserved.
		lines = append(lines, u.EscapedPath())
	}
	lines = append(lines, policyLines(p)...)
	lines = append(lines, strconv.FormatInt(expires, 10), secret)
	return strings.Join(lines, "\n")
}

func policyLines(p policy) []string {
	lines := make([]string, 0, len(p))
	for k, v := range p {
		if k == "method" || k == "path_prefix" {
			continue
		}
		lines = append(lines, k+":"+v)
	}
	slices.Sort(lines)
	return lines
}

// signature returns URL-safe base64 (no padding) of the raw hash of s.
// newHash is called per invocation so the Signer stays goroutine-safe.
func signature(newHash func() hash.Hash, s string) string {
	h := newHash()
	h.Write([]byte(s)) // hash.Hash.Write never returns an error
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// queryParams builds the x_ark_* query map. method is omitted; client_ip and
// user_agent are masked to "1"; everything else is carried verbatim.
func queryParams(accessID string, expires int64, sig string, p policy) map[string]string {
	q := map[string]string{
		"x_ark_access_id": accessID,
		"x_ark_auth_type": authType,
		"x_ark_expires":   strconv.FormatInt(expires, 10),
		"x_ark_signature": sig,
	}
	for k, v := range p {
		switch k {
		case "method":
			continue
		case "client_ip", "user_agent":
			q["x_ark_"+k] = "1"
		default:
			q["x_ark_"+k] = v
		}
	}
	return q
}

// serializeQuery joins params sorted by key. With skipURLEncoding=false the
// values are form-encoded per RFC 1738.
func serializeQuery(params map[string]string, skipURLEncoding bool) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		v := params[k]
		if !skipURLEncoding {
			v = formEncode(v)
		}
		pairs = append(pairs, k+"="+v)
	}
	return strings.Join(pairs, "&")
}

// formEncode applies form encoding per RFC 1738: like url.QueryEscape (space
// becomes '+') but '~' becomes %7E as well.
func formEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "~", "%7E")
}

// policyFromQuery rebuilds the policy from x_ark_* query keys, excluding the
// four envelope keys. Values are as carried on the wire ("1" for masked keys).
func policyFromQuery(q url.Values) policy {
	p := make(policy)
	for k, vs := range q {
		if !strings.HasPrefix(k, "x_ark_") {
			continue
		}
		if isEnvelopeKey(k) || len(vs) == 0 {
			continue
		}
		p[strings.TrimPrefix(k, "x_ark_")] = vs[0]
	}
	return p
}
