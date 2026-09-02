package bytearksigner

import (
	"crypto/subtle"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Renew issues a fresh expiry and signature for an already-signed ark-v2 URL
// and changes nothing else: the returned string is signedURL with the values of
// x_ark_expires and x_ark_signature replaced in place, so every other query
// parameter keeps its original spelling, encoding and position, and the fragment
// is preserved.
//
// Renew is the strict counterpart of Reissue. It refuses to touch a URL whose
// current signature it cannot check: the ark-v2 envelope must be complete
// (x_ark_auth_type, x_ark_expires, x_ark_signature and x_ark_access_id all
// present and well formed), and the existing signature must verify with this
// Signer's access secret. Whether that signature has lapsed is not checked —
// extending an expired URL is what Renew is for.
//
// The access ID is not compared: a signature depends on the secret alone, and
// several access IDs may be aliases of one secret. x_ark_access_id is passed
// through untouched, so the renewed URL carries whatever access ID it arrived
// with — use Reissue to move a URL onto this Signer's own credentials.
//
// Because the policy may not change, conds may only supply what the wire cannot
// carry: ClientIP and UserAgent for keys already masked as "1" on the URL, and
// Method. A condition that sets any other policy key, that masks a key the URL
// does not carry, or that removes a key (Without) is rejected with
// ErrPolicyChange. Use Reissue to change a policy.
//
// A zero expires means now plus the Signer's default age.
//
// The returned error matches (errors.Is) one of ErrMalformed, ErrNotSigned,
// ErrPolicyChange, ErrMaskedValue, ErrPathPrefix or ErrSignature.
func (s *Signer) Renew(signedURL string, expires time.Time, conds ...Condition) (string, error) {
	u, err := url.Parse(signedURL)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	segs := querySegments(u.RawQuery)
	// A repeated envelope key is ambiguous: the CDN and net/url would each pick
	// a value, and an in-place replacement would leave the other one behind.
	if countSegments(segs, "x_ark_expires") > 1 || countSegments(segs, "x_ark_signature") > 1 {
		return "", fmt.Errorf("%w: duplicate ark-v2 envelope parameter", ErrMalformed)
	}

	q := u.Query()
	if q.Get("x_ark_auth_type") != authType {
		return "", fmt.Errorf("%w: x_ark_auth_type is not %q", ErrNotSigned, authType)
	}
	exp, err := strconv.ParseInt(q.Get("x_ark_expires"), 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: x_ark_expires is not an integer", ErrNotSigned)
	}
	sig := q.Get("x_ark_signature")
	if sig == "" {
		return "", fmt.Errorf("%w: x_ark_signature is empty", ErrNotSigned)
	}
	if _, ok := q["x_ark_access_id"]; !ok {
		return "", fmt.Errorf("%w: x_ark_access_id is absent", ErrNotSigned)
	}

	p := policyFromQuery(q)
	for _, c := range conds {
		if c == nil {
			continue
		}
		if err := checkRenewCondition(c, p); err != nil {
			return "", err
		}
		c(p)
	}
	if err := p.checkMaskedResolved(); err != nil {
		return "", err
	}

	bare := *u
	bare.RawQuery, bare.ForceQuery, bare.Fragment, bare.RawFragment = "", false, "", ""
	if prefix, ok := p.pathPrefix(); ok && !strings.HasPrefix(u.EscapedPath(), prefix) {
		return "", ErrPathPrefix
	}
	want := signature(s.newHash, stringToSign(&bare, exp, p, s.accessSecret))
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return "", ErrSignature
	}

	if expires.IsZero() {
		expires = time.Now().Add(s.defaultAge)
	}
	newExp := expires.Unix()
	newSig := signature(s.newHash, stringToSign(&bare, newExp, p, s.accessSecret))

	// Byte surgery on the original string: only the two envelope values move.
	// Both replacements are URL-safe as written (decimal digits, and base64url
	// which neither encoding mode escapes), so no re-encoding is needed.
	for i, seg := range segs {
		switch segmentKey(seg) {
		case "x_ark_expires":
			segs[i] = "x_ark_expires=" + strconv.FormatInt(newExp, 10)
		case "x_ark_signature":
			segs[i] = "x_ark_signature=" + newSig
		}
	}
	mark := strings.Index(signedURL, "?")
	if mark < 0 || !strings.HasPrefix(signedURL[mark+1:], u.RawQuery) {
		// Unreachable for a URL that parsed and carries a query string.
		return "", fmt.Errorf("%w: query string is not a literal substring of the URL", ErrMalformed)
	}
	return signedURL[:mark+1] + strings.Join(segs, "&") + signedURL[mark+1+len(u.RawQuery):], nil
}

// Reissue re-signs rawURL with this Signer's credentials, allowing the policy to
// change. The ark-v2 envelope of the input (x_ark_access_id, x_ark_auth_type,
// x_ark_expires, x_ark_signature) is discarded and never verified; the remaining
// x_ark_* parameters become the base policy, conds are applied on top in order
// (the typed conditions and Custom set or override a key, Without removes one),
// and the result is signed afresh. Reissue is therefore the key-rotation path:
// the output carries this Signer's access ID.
//
// Query parameters that do not start with "x_ark_" are preserved verbatim, in
// their original order, ahead of the freshly serialised ark-v2 parameters; the
// fragment, if any, is preserved as written. Reissue is also the only way to
// sign a URL that already carries a query string, which Sign rejects with
// ErrURLHasQuery.
//
// A zero expires means now plus the Signer's default age.
//
// Because a masked condition carried as the literal "1" cannot produce a URL the
// CDN will accept, Reissue returns ErrMaskedValue when x_ark_client_ip or
// x_ark_user_agent is still "1" after conds; pass ClientIP or UserAgent with the
// real value. The returned error matches (errors.Is) ErrMalformed or
// ErrMaskedValue.
func (s *Signer) Reissue(rawURL string, expires time.Time, conds ...Condition) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	p := policyFromQuery(u.Query())
	for _, c := range conds {
		if c != nil {
			c(p)
		}
	}
	if err := p.checkMaskedResolved(); err != nil {
		return "", err
	}
	if expires.IsZero() {
		expires = time.Now().Add(s.defaultAge)
	}
	exp := expires.Unix()

	bare := *u
	bare.RawQuery, bare.ForceQuery, bare.Fragment, bare.RawFragment = "", false, "", ""
	sig := signature(s.newHash, stringToSign(&bare, exp, p, s.accessSecret))

	// Keep the caller's own parameters exactly as they were written.
	segs := querySegments(u.RawQuery)
	kept := make([]string, 0, len(segs))
	for _, seg := range segs {
		if seg == "" || strings.HasPrefix(segmentKey(seg), "x_ark_") {
			continue
		}
		kept = append(kept, seg)
	}
	query := serializeQuery(queryParams(s.accessID, exp, sig, p), s.skipURLEncoding)
	if len(kept) > 0 {
		query = strings.Join(kept, "&") + "&" + query
	}

	base := rawURL
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		base = rawURL[:i]
	}
	fragment := ""
	if i := strings.Index(rawURL, "#"); i >= 0 {
		fragment = rawURL[i:]
	}
	return base + "?" + query + fragment, nil
}

// querySegments splits a raw query string on '&'. Empty segments are kept, so
// that joining the result reproduces rawQuery byte-for-byte.
func querySegments(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	return strings.Split(rawQuery, "&")
}

// segmentKey returns the key part of a raw "key=value" query segment.
func segmentKey(segment string) string {
	if i := strings.Index(segment, "="); i >= 0 {
		return segment[:i]
	}
	return segment
}

func countSegments(segs []string, key string) int {
	n := 0
	for _, seg := range segs {
		if segmentKey(seg) == key {
			n++
		}
	}
	return n
}

// checkRenewCondition reports whether c is admissible in Renew, which may not
// change the policy: it may only fill in a value the wire masks as "1", or set
// the method, which never appears on the wire at all.
func checkRenewCondition(c Condition, p policy) error {
	// What c sets is discovered on a scratch policy, so a condition that writes
	// the value already on the wire is still recognised as touching that key.
	probe := make(policy)
	c(probe)
	for k := range probe {
		switch k {
		case "method":
		case "client_ip", "user_agent":
			if p[k] != maskedValue {
				return fmt.Errorf("%w: %s is not masked on the signed URL", ErrPolicyChange, k)
			}
		default:
			return fmt.Errorf("%w: cannot set %s on an already-signed URL", ErrPolicyChange, k)
		}
	}
	// What c removes is discovered on a copy of the real policy, since a
	// removal leaves no trace on an empty one.
	after := p.clone()
	c(after)
	for k := range p {
		if _, ok := after[k]; !ok {
			return fmt.Errorf("%w: cannot remove %s from an already-signed URL", ErrPolicyChange, k)
		}
	}
	return nil
}
