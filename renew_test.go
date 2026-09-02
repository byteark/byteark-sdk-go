package bytearksigner_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

// referenceVector returns the reference vector called name.
func referenceVector(t *testing.T, g referenceFile, name string) vector {
	t.Helper()
	for _, v := range g.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("reference vector %q not found", name)
	return vector{}
}

// signerForVector builds a Signer with the credentials and encoding mode the
// vector was generated with.
func signerForVector(t *testing.T, g referenceFile, v vector) *bytearksigner.Signer {
	t.Helper()
	id, secret := g.credentialsFor(v)
	s, err := bytearksigner.New(id, secret, bytearksigner.WithSkipURLEncoding(v.SkipURLEncoding))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// queryOf returns everything after the first '?' of rawURL.
func queryOf(t *testing.T, rawURL string) string {
	t.Helper()
	i := strings.Index(rawURL, "?")
	if i < 0 {
		t.Fatalf("no query string in %q", rawURL)
	}
	return rawURL[i+1:]
}

// renewTwins pairs a reference vector with the vector that is identical to it
// except for a 3600s-later expiry, plus the conditions a verifier must supply
// because they are masked on the wire.
var renewTwins = []struct {
	from, to string
	conds    []bytearksigner.Condition
}{
	{from: "path_prefix", to: "path_prefix_renewed"},
	{from: "client_ip", to: "client_ip_renewed",
		conds: []bytearksigner.Condition{bytearksigner.ClientIP("103.253.132.65")}},
	{from: "user_agent", to: "user_agent_renewed",
		conds: []bytearksigner.Condition{bytearksigner.UserAgent("Mozilla/5.0 (X11; Linux x86_64)")}},
	{from: "custom_option_origin", to: "custom_option_origin_renewed"},
	{from: "host_with_port", to: "host_with_port_renewed"},
}

func TestRenewMatchesReferenceTwins(t *testing.T) {
	g := loadReference(t)
	for _, tw := range renewTwins {
		t.Run(tw.from, func(t *testing.T) {
			from := referenceVector(t, g, tw.from)
			to := referenceVector(t, g, tw.to)
			s := signerForVector(t, g, from)
			got, err := s.Renew(from.SignedURL, time.Unix(to.Expires, 0), tw.conds...)
			if err != nil {
				t.Fatalf("Renew: %v", err)
			}
			if got != to.SignedURL {
				t.Errorf("wire drift\n got: %s\nwant: %s", got, to.SignedURL)
			}
		})
	}
}

func TestRenewPreservesExtraBytes(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "path_prefix")
	to := referenceVector(t, g, "path_prefix_renewed")
	s := signerForVector(t, g, from)
	got, err := s.Renew(from.SignedURL+"&foo=bar"+"#frag", time.Unix(to.Expires, 0))
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if want := to.SignedURL + "&foo=bar" + "#frag"; got != want {
		t.Errorf("wire drift\n got: %s\nwant: %s", got, want)
	}
}

func TestRenewDefaultAge(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "path_prefix")
	s := signerForVector(t, g, from)
	got, err := s.Renew(from.SignedURL, time.Time{})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := s.Verify(got, time.Now()); err != nil {
		t.Errorf("Verify after default-age renew: %v", err)
	}
}

// TestRenewIgnoresLapsedExpiry: the source vector's own expiry lapsed in 2018,
// and renewing an already-expired URL is exactly what Renew is for.
func TestRenewIgnoresLapsedExpiry(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "path_prefix")
	s := signerForVector(t, g, from)
	at := time.Now().Add(30 * time.Minute)
	got, err := s.Renew(from.SignedURL, at)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := s.Verify(got, at.Add(-time.Minute)); err != nil {
		t.Errorf("Verify at new expiry: %v", err)
	}
	if err := s.Verify(got, at.Add(time.Minute)); !errors.Is(err, bytearksigner.ErrExpired) {
		t.Errorf("past the new expiry: err = %v want ErrExpired", err)
	}
}

func TestRenewErrors(t *testing.T) {
	g := loadReference(t)
	pathPrefix := referenceVector(t, g, "path_prefix")
	clientIP := referenceVector(t, g, "client_ip")
	basic := referenceVector(t, g, "basic_get")
	s := signerForVector(t, g, pathPrefix)
	exp := time.Unix(pathPrefix.Expires+3600, 0)

	tests := []struct {
		name  string
		input string
		conds []bytearksigner.Condition
		want  error
	}{
		{name: "unparsable", input: "://bad", want: bytearksigner.ErrMalformed},
		{name: "plain url", input: testURL, want: bytearksigner.ErrNotSigned},
		{name: "no auth type", input: strings.Replace(pathPrefix.SignedURL, "x_ark_auth_type=ark-v2", "x_ark_auth_type=ark-v1", 1), want: bytearksigner.ErrNotSigned},
		{name: "expires not an int", input: strings.Replace(pathPrefix.SignedURL, "x_ark_expires=1514764800", "x_ark_expires=soon", 1), want: bytearksigner.ErrNotSigned},
		{name: "duplicate expires", input: pathPrefix.SignedURL + "&x_ark_expires=1514768400", want: bytearksigner.ErrMalformed},
		{name: "duplicate signature", input: pathPrefix.SignedURL + "&x_ark_signature=334wInm0jKfC6LCm23zndA", want: bytearksigner.ErrMalformed},
		{name: "altered path prefix", input: strings.Replace(pathPrefix.SignedURL, "x_ark_path_prefix=%2Fvideo-objects%2FQDuxJm02TYqJ%2F", "x_ark_path_prefix=%2Fvideo-objects%2F", 1), want: bytearksigner.ErrSignature},
		{name: "altered signature", input: strings.Replace(pathPrefix.SignedURL, "x_ark_signature=", "x_ark_signature=x", 1), want: bytearksigner.ErrSignature},
		{name: "path outside prefix", input: strings.Replace(pathPrefix.SignedURL, "/video-objects/QDuxJm02TYqJ/playlist.m3u8", "/video-objects/OTHER/playlist.m3u8", 1), want: bytearksigner.ErrPathPrefix},
		{name: "policy change path prefix", input: pathPrefix.SignedURL, conds: []bytearksigner.Condition{bytearksigner.PathPrefix("/video-objects/")}, want: bytearksigner.ErrPolicyChange},
		{name: "policy change custom", input: pathPrefix.SignedURL, conds: []bytearksigner.Condition{bytearksigner.Custom("viewer_group", "vip")}, want: bytearksigner.ErrPolicyChange},
		{name: "policy change without", input: pathPrefix.SignedURL, conds: []bytearksigner.Condition{bytearksigner.Without("path_prefix")}, want: bytearksigner.ErrPolicyChange},
		{name: "masked key not on wire", input: basic.SignedURL, conds: []bytearksigner.Condition{bytearksigner.ClientIP("1.2.3.4")}, want: bytearksigner.ErrPolicyChange},
		{name: "masked value left on wire", input: clientIP.SignedURL, want: bytearksigner.ErrMaskedValue},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Renew(tc.input, exp, tc.conds...); !errors.Is(err, tc.want) {
				t.Errorf("err = %v want %v", err, tc.want)
			}
		})
	}
}

// TestRenewIgnoresAccessID: the signature depends on the secret alone, so a
// Signer holding a different access ID over the same secret renews the twin
// byte-for-byte — and the output keeps the access ID the input carried, not the
// Signer's.
func TestRenewIgnoresAccessID(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "path_prefix")
	to := referenceVector(t, g, "path_prefix_renewed")
	other, err := bytearksigner.New("some-other-access-id", g.AccessSecret,
		bytearksigner.WithSkipURLEncoding(from.SkipURLEncoding))
	if err != nil {
		t.Fatal(err)
	}
	got, err := other.Renew(from.SignedURL, time.Unix(to.Expires, 0))
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if got != to.SignedURL {
		t.Errorf("wire drift\n got: %s\nwant: %s", got, to.SignedURL)
	}
	if strings.Contains(got, "some-other-access-id") {
		t.Errorf("Renew overwrote x_ark_access_id: %s", got)
	}
}

// TestRenewWrongSecret: a different secret cannot reproduce the existing
// signature, so Renew refuses the URL.
func TestRenewWrongSecret(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "path_prefix")
	rotated := referenceVector(t, g, "rotated_basic_path_prefix")
	id, secret := g.credentialsFor(rotated)
	other, err := bytearksigner.New(id, secret,
		bytearksigner.WithSkipURLEncoding(from.SkipURLEncoding))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Renew(from.SignedURL, time.Unix(from.Expires+3600, 0)); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("err = %v want ErrSignature", err)
	}
}

// TestRenewAcceptsMethodCondition: the method never appears on the wire, so
// supplying it is not a policy change — but supplying the wrong one fails the
// signature check.
func TestRenewAcceptsMethodCondition(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "method_post")
	s := signerForVector(t, g, from)
	got, err := s.Renew(from.SignedURL, time.Unix(from.Expires+3600, 0), bytearksigner.Method("POST"))
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := s.Verify(got, time.Unix(from.Expires, 0), bytearksigner.Method("POST")); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if _, err := s.Renew(from.SignedURL, time.Unix(from.Expires+3600, 0), bytearksigner.Method("GET")); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("wrong method: err = %v want ErrSignature", err)
	}
}

func TestReissueMatchesReferencePair(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "reissue_from")
	to := referenceVector(t, g, "reissue_to")
	s := signerForVector(t, g, from)
	got, err := s.Reissue(from.SignedURL, time.Unix(to.Expires, 0),
		bytearksigner.Without("viewer_group"),
		bytearksigner.PathPrefix("/video-objects/"))
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if got != to.SignedURL {
		t.Errorf("wire drift\n got: %s\nwant: %s", got, to.SignedURL)
	}
}

func TestReissueRotatesCredentials(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "path_prefix")
	to := referenceVector(t, g, "rotated_basic_path_prefix")
	rotated := signerForVector(t, g, to)
	got, err := rotated.Reissue(from.SignedURL, time.Unix(to.Expires, 0))
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if got != to.SignedURL {
		t.Errorf("wire drift\n got: %s\nwant: %s", got, to.SignedURL)
	}
}

func TestReissuePreservesNonArkParams(t *testing.T) {
	g := loadReference(t)
	to := referenceVector(t, g, "path_prefix")
	s := signerForVector(t, g, to)
	stale := testURL + "?quality=720p" +
		"&x_ark_access_id=stale&x_ark_auth_type=ark-v2&x_ark_expires=1&x_ark_signature=bad" +
		"&x_ark_path_prefix=%2Fvideo-objects%2FQDuxJm02TYqJ%2F"
	got, err := s.Reissue(stale, time.Unix(to.Expires, 0))
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	want := testURL + "?quality=720p&" + queryOf(t, to.SignedURL)
	if got != want {
		t.Errorf("wire drift\n got: %s\nwant: %s", got, want)
	}
}

func TestReissueAcceptsURLWithQuerySignRejects(t *testing.T) {
	s := newTestSigner(t)
	raw := testURL + "?quality=720p"
	if _, err := s.Sign(raw, expiry); !errors.Is(err, bytearksigner.ErrURLHasQuery) {
		t.Errorf("Sign: err = %v want ErrURLHasQuery", err)
	}
	got, err := s.Reissue(raw, expiry)
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if !strings.HasPrefix(got, raw+"&x_ark_access_id=") {
		t.Errorf("non-ark param not preserved first: %s", got)
	}
	if err := s.Verify(got, signedAt); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestReissueMaskedValue(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "client_ip")
	s := signerForVector(t, g, from)
	if _, err := s.Reissue(from.SignedURL, time.Unix(from.Expires, 0)); !errors.Is(err, bytearksigner.ErrMaskedValue) {
		t.Errorf("err = %v want ErrMaskedValue", err)
	}
	got, err := s.Reissue(from.SignedURL, time.Unix(from.Expires, 0), bytearksigner.ClientIP("103.253.132.65"))
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if err := s.Verify(got, time.Unix(from.Expires-1, 0), bytearksigner.ClientIP("103.253.132.65")); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestReissueOutputVerifies(t *testing.T) {
	g := loadReference(t)
	for _, v := range g.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if wantPathPrefixReject(t, v.SignedURL) {
				t.Skip("vector declares a path_prefix its own path is not under")
			}
			s := signerForVector(t, g, v)
			conds := conditionsFromOptions(v.Options)
			got, err := s.Reissue(v.SignedURL, time.Unix(v.Expires, 0), conds...)
			if err != nil {
				t.Fatalf("Reissue: %v", err)
			}
			if err := s.Verify(got, time.Unix(v.Expires-1, 0), conds...); err != nil {
				t.Errorf("Verify(%s) = %v", got, err)
			}
		})
	}
}

func TestReissueMalformed(t *testing.T) {
	s := newTestSigner(t)
	if _, err := s.Reissue("://bad", expiry); !errors.Is(err, bytearksigner.ErrMalformed) {
		t.Errorf("err = %v want ErrMalformed", err)
	}
}

func TestWithoutIsNoOpOnSign(t *testing.T) {
	s := newTestSigner(t)
	want, err := s.Sign(testURL, expiry, bytearksigner.PathPrefix("/video-objects/"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Sign(testURL, expiry,
		bytearksigner.PathPrefix("/video-objects/"), bytearksigner.Without("client_ip"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Without changed Sign output\n got: %s\nwant: %s", got, want)
	}
}

func TestWithoutDropsKeyOnReissue(t *testing.T) {
	g := loadReference(t)
	from := referenceVector(t, g, "reissue_from")
	s := signerForVector(t, g, from)
	got, err := s.Reissue(from.SignedURL, time.Unix(from.Expires, 0), bytearksigner.Without("viewer-group"))
	if err != nil {
		t.Fatalf("Reissue: %v", err)
	}
	if strings.Contains(got, "x_ark_viewer_group") {
		t.Errorf("viewer_group survived Without: %s", got)
	}
	if err := s.Verify(got, time.Unix(from.Expires-1, 0)); err != nil {
		t.Errorf("Verify: %v", err)
	}
}
