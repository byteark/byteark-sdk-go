package bytearksigner

import (
	"crypto/md5"
	"crypto/subtle"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultAge is the signed-URL lifetime used when Sign receives a zero expires.
const DefaultAge = 900 * time.Second

// Signer signs and verifies ark-v2 URLs for one credential pair. It is
// immutable after New and safe for concurrent use.
type Signer struct {
	accessID        string
	accessSecret    string
	defaultAge      time.Duration
	skipURLEncoding bool
	newHash         func() hash.Hash
}

// Option configures a Signer at construction time.
type Option func(*Signer) error

// WithDefaultAge sets the lifetime used when Sign is given a zero expires (default 900s).
func WithDefaultAge(d time.Duration) Option {
	return func(s *Signer) error {
		if d <= 0 {
			return fmt.Errorf("bytearksigner: default age must be positive, got %v", d)
		}
		s.defaultAge = d
		return nil
	}
}

// WithSkipURLEncoding disables URL-encoding of query values. The default
// (false) form-encodes them per RFC 1738 (space becomes '+', '~' becomes %7E),
// which is what the CDN expects. Only enable it if you need byte-identical
// output to the v1 Go SDK's default.
func WithSkipURLEncoding(skip bool) Option {
	return func(s *Signer) error { s.skipURLEncoding = skip; return nil }
}

// WithHasher replaces the MD5 hash used for signatures. newHash is called once
// per Sign/Verify. Only use this if your CDN verifier is configured to match.
func WithHasher(newHash func() hash.Hash) Option {
	return func(s *Signer) error {
		if newHash == nil {
			return fmt.Errorf("bytearksigner: hasher constructor must not be nil")
		}
		s.newHash = newHash
		return nil
	}
}

// New creates a Signer. accessSecret is required; accessID may be empty.
func New(accessID, accessSecret string, opts ...Option) (*Signer, error) {
	if accessSecret == "" {
		return nil, ErrMissingSecret
	}
	s := &Signer{
		accessID:     accessID,
		accessSecret: accessSecret,
		defaultAge:   DefaultAge,
		newHash:      md5.New,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Sign returns rawURL with the ark-v2 query string appended. rawURL must not
// already contain a query string. A zero expires means now + default age.
func (s *Signer) Sign(rawURL string, expires time.Time, conds ...Condition) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("bytearksigner: parse url: %w", err)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", ErrURLHasQuery
	}
	if expires.IsZero() {
		expires = time.Now().Add(s.defaultAge)
	}
	exp := expires.Unix()
	p := newPolicy(conds)
	sig := signature(s.newHash, stringToSign(u, exp, p, s.accessSecret))
	q := serializeQuery(queryParams(s.accessID, exp, sig, p), s.skipURLEncoding)
	return rawURL + "?" + q, nil
}

// Verify checks that signedURL was produced by this Signer's credentials and is
// still valid at time at. Conditions that are masked on the wire (ClientIP,
// UserAgent) and the request Method are not recoverable from the URL, so the
// caller passes the actual request values as conds; they override any wire value.
//
// Returns nil when valid, otherwise an error matching (errors.Is) one of
// ErrMalformed, ErrExpired, ErrPathPrefix or ErrSignature.
func (s *Signer) Verify(signedURL string, at time.Time, conds ...Condition) error {
	u, err := url.Parse(signedURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	q := u.Query()
	exp, err := strconv.ParseInt(q.Get("x_ark_expires"), 10, 64)
	if err != nil || q.Get("x_ark_signature") == "" {
		return ErrMalformed
	}
	if at.IsZero() {
		at = time.Now()
	}
	if at.After(time.Unix(exp, 0)) {
		return ErrExpired
	}
	p := policyFromQuery(q)
	for _, c := range conds {
		if c != nil {
			c(p)
		}
	}
	if prefix, ok := p.pathPrefix(); ok && !strings.HasPrefix(u.EscapedPath(), prefix) {
		return ErrPathPrefix
	}
	bare := *u
	bare.RawQuery, bare.ForceQuery, bare.Fragment = "", false, ""
	want := signature(s.newHash, stringToSign(&bare, exp, p, s.accessSecret))
	if subtle.ConstantTimeCompare([]byte(want), []byte(q.Get("x_ark_signature"))) != 1 {
		return ErrSignature
	}
	return nil
}
