// Use-case coverage. Each test names one delivery shape by its public meaning —
// playlist delivery with a path prefix and a masked client IP, a storyboard cue,
// a subtitle track, an asset behind an explicit host:port, and so on — and
// drives Sign or Verify with the conditions that shape implies.
//
// Expectations for Sign are frozen reference vectors, loaded from
// testdata/reference_vectors.json BY NAME. No signature, signed URL or query
// string is typed into this file, and nothing here asserts against this
// module's own output.
//
// Expectations for Verify are the documented sentinels: see the godoc on
// Signer.Verify and the sentinel values in errors.go. They are asserted with
// errors.Is, never as error strings. The subjects are the same reference
// vectors, named the same way.
package bytearksigner_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

// Values that appear as Sign/Verify *inputs* below. They are cross-checked
// implicitly: a wrong input yields a wrong signature, which fails the
// comparison against the reference vector.
const (
	ucRequestTags      = "ark-strm-proj:aBcD1234,ark-strm-cid:QDuxJm02TYqJ"
	ucClientIP         = "103.253.132.65"
	ucUserAgent        = "Mozilla/5.0 (X11; Linux x86_64)"
	ucReferer          = "https://player.example.com/"
	ucPlaylistPrefix   = "/stream-playlist/QDuxJm02TYqJ/"
	ucStoryboardPrefix = "/stream-playlist/QDuxJm02TYqJ/storyboard/sb01/"
	ucTokenPathPrefix  = "/stream-playlist/QDuxJm02TYqJ/eyJhbGciOiJIUzI1NiJ9.eyJrIjoxfQ.abc-_123/"
	ucBumperPrefix     = "/bumpers/intro/"
)

// referenceVector (renew_test.go) looks a vector up by name, and
// signerForVector (renew_test.go) builds the Signer it was generated with.

// assertSignsTo signs the named vector's URL and expiry with conds and requires
// the result to equal the vector's reference signed URL byte-for-byte.
func assertSignsTo(t *testing.T, name string, conds ...bytearksigner.Condition) vector {
	t.Helper()
	g := loadReference(t)
	v := referenceVector(t, g, name)
	s := signerForVector(t, g, v)
	got, err := s.Sign(v.URL, time.Unix(v.Expires, 0), conds...)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != v.SignedURL {
		t.Errorf("wire drift against reference vector %q\n got: %s\nwant: %s", name, got, v.SignedURL)
	}
	return v
}

// -----------------------------------------------------------------------------
// Sign: playlist delivery with egress parameters
// -----------------------------------------------------------------------------

func TestSignPlaylistWithPathPrefixAndMaskedClientIP(t *testing.T) {
	assertSignsTo(t, "playlist_path_prefix_client_ip",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucPlaylistPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.ClientIP(ucClientIP),
	)
}

func TestSignPlaylistWithFullEgressParameterSet(t *testing.T) {
	assertSignsTo(t, "playlist_full_egress_params",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucPlaylistPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("viewer_group", "premium"),
		bytearksigner.Custom("origin", "1"),
		bytearksigner.Custom("playback_origin", "https%3A%2F%2Fplayer.example.com"),
		bytearksigner.Custom("max_resolution", "1080p"),
		bytearksigner.Custom("referer", ucReferer),
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
		bytearksigner.Custom("resolution", "720p"),
		bytearksigner.Custom("geo_allow", "TH,SG"),
		bytearksigner.Custom("geo_block", "CN,RU"),
	)
}

func TestSignPlaylistWithGeoAllowAllAndExclusiveClientIP(t *testing.T) {
	assertSignsTo(t, "playlist_geo_allow_all_exclusive_ip",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucPlaylistPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("geo_allow", "ALL"),
		bytearksigner.ClientIP(ucClientIP),
	)
}

func TestSignPlaylistWithExportToken(t *testing.T) {
	assertSignsTo(t, "playlist_export_token",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucPlaylistPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("export_token", "eyJhbGciOiJIUzI1NiJ9.eyJ2IjoxfQ.sig-token_123"),
	)
}

// The prefix carries an opaque token as a path segment, so it contains dots and
// URL-safe base64 characters that must survive percent-encoding unchanged.
func TestSignPlaylistWithTokenPathSegmentInPrefix(t *testing.T) {
	assertSignsTo(t, "playlist_jwt_path_segment",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucTokenPathPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
	)
}

// -----------------------------------------------------------------------------
// Sign: storyboard, waveform and media-info assets
// -----------------------------------------------------------------------------

func TestSignStoryboardCueWithPathPrefix(t *testing.T) {
	assertSignsTo(t, "storyboard_cue_path_prefix",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucStoryboardPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("geo_allow", "TH,SG"),
		bytearksigner.Custom("geo_block", "CN,RU"),
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
		bytearksigner.Custom("referer", ucReferer),
		bytearksigner.Custom("max_resolution", "1080p"),
	)
}

// No PathPrefix condition: the whole URL path is signed instead of a prefix.
func TestSignWithoutPathPrefixSignsTheFullPath(t *testing.T) {
	assertSignsTo(t, "waveform_no_path_prefix",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("geo_allow", "TH,SG"),
		bytearksigner.Custom("geo_block", "CN,RU"),
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
		bytearksigner.Custom("referer", ucReferer),
		bytearksigner.Custom("max_resolution", "1080p"),
	)
}

func TestSignSubtitleTrackWithoutPathPrefix(t *testing.T) {
	assertSignsTo(t, "storyboard_vtt_no_path_prefix",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("geo_allow", "TH,SG"),
		bytearksigner.Custom("geo_block", "CN,RU"),
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
		bytearksigner.Custom("referer", ucReferer),
	)
}

func TestSignSubtitleTrackWithTokenPathSegment(t *testing.T) {
	assertSignsTo(t, "storyboard_vtt_transform_token",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("geo_allow", "TH,SG"),
		bytearksigner.Custom("geo_block", "CN,RU"),
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
		bytearksigner.Custom("referer", ucReferer),
	)
}

func TestSignMediaInfoWithMaxResolution(t *testing.T) {
	assertSignsTo(t, "media_info_max_resolution",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.Custom("request_tags", ucRequestTags),
		bytearksigner.Custom("geo_allow", "TH,SG"),
		bytearksigner.Custom("geo_block", "CN,RU"),
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
		bytearksigner.Custom("referer", ucReferer),
		bytearksigner.Custom("max_resolution", "1080p"),
	)
}

// -----------------------------------------------------------------------------
// Sign: explicit host:port subject
// -----------------------------------------------------------------------------

// The subject carries an explicit port, which stays on the signed host line.
func TestSignHostWithExplicitPortAndPathPrefix(t *testing.T) {
	assertSignsTo(t, "bumper_host_port_path_prefix",
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucBumperPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
	)
}

// -----------------------------------------------------------------------------
// Sign then post-process: bare (non-x_ark_) query parameters
// -----------------------------------------------------------------------------

// A bare (non-x_ark_) parameter is added to the signed query after signing. The
// signed URL itself must equal the reference vector, and the extra parameter
// must not disturb verification in either position.
func TestSignThenAddBareQueryParameterStillVerifies(t *testing.T) {
	g := loadReference(t)
	v := referenceVector(t, g, "bare_param_prepend_base")
	s := signerForVector(t, g, v)

	signed, err := s.Sign(v.URL, time.Unix(v.Expires, 0),
		bytearksigner.Method(http.MethodGet),
		bytearksigner.PathPrefix(ucPlaylistPrefix),
		bytearksigner.Custom("request_tags", ucRequestTags),
	)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed != v.SignedURL {
		t.Fatalf("wire drift against reference vector %q\n got: %s\nwant: %s",
			v.Name, signed, v.SignedURL)
	}

	at := time.Unix(v.Expires-1, 0)
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"appended", v.SignedURL + "&resolution=720p"},
		{"prepended", prependQueryParam(v.SignedURL, "resolution", "720p")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Verify(tc.url, at); err != nil {
				t.Errorf("Verify: got %v, want nil", err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Verify: documented sentinel expectations (see the file header)
// -----------------------------------------------------------------------------

// verifySubject returns the reference vector named name and a Signer built with
// the credentials and encoding mode that vector was generated with.
func verifySubject(t *testing.T, name string) (*bytearksigner.Signer, vector) {
	t.Helper()
	g := loadReference(t)
	v := referenceVector(t, g, name)
	return signerForVector(t, g, v), v
}

// maskedSubject is the shape a request-time verifier sees: a path prefix plus
// both masked conditions, so the caller must supply the real values.
const maskedSubjectVector = "storyboard_cue_path_prefix"

// plainSubject carries neither masked condition.
const plainSubjectVector = "bare_param_prepend_base"

func maskedConds() []bytearksigner.Condition {
	return []bytearksigner.Condition{
		bytearksigner.ClientIP(ucClientIP),
		bytearksigner.UserAgent(ucUserAgent),
	}
}

func TestVerifyAcceptsValidURLWithMaskedValuesSupplied(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	if err := s.Verify(v.SignedURL, time.Unix(v.Expires-1, 0), maskedConds()...); err != nil {
		t.Errorf("Verify: got %v, want nil", err)
	}
}

func TestVerifyAcceptsTheExpiryInstantItself(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	if err := s.Verify(v.SignedURL, time.Unix(v.Expires, 0), maskedConds()...); err != nil {
		t.Errorf("Verify at the expiry instant: got %v, want nil", err)
	}
}

func TestVerifyRejectsExpiredURL(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	err := s.Verify(v.SignedURL, time.Unix(v.Expires+1, 0), maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsWhenMaskedValuesAreNotSupplied(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	at := time.Unix(v.Expires-1, 0)
	for _, tc := range []struct {
		name  string
		conds []bytearksigner.Condition
	}{
		{"none supplied", nil},
		{"only the client IP supplied", []bytearksigner.Condition{bytearksigner.ClientIP(ucClientIP)}},
		{"wrong client IP supplied", []bytearksigner.Condition{
			bytearksigner.ClientIP("1.2.3.4"), bytearksigner.UserAgent(ucUserAgent)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Verify(v.SignedURL, at, tc.conds...)
			if !errors.Is(err, bytearksigner.ErrSignature) {
				t.Errorf("got %v, want ErrSignature", err)
			}
		})
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	err := s.Verify(tamperSignature(v.SignedURL), time.Unix(v.Expires-1, 0), maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

// A verifier holding a different credential pair must report ErrSignature and
// nothing else, so a caller can fall through to the next key.
func TestVerifyWithForeignSecretReportsSignatureError(t *testing.T) {
	_, v := verifySubject(t, maskedSubjectVector)
	other, err := bytearksigner.New("test-other-access-id", "test-other-secret-not-real")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = other.Verify(v.SignedURL, time.Unix(v.Expires-1, 0), maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsPathOutsideSignedPrefix(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	sibling := strings.Replace(v.SignedURL, ucStoryboardPrefix, "/stream-playlist/OTHERVIDEO/", 1)
	if sibling == v.SignedURL {
		t.Fatal("test setup: subject path was not rewritten")
	}
	err := s.Verify(sibling, time.Unix(v.Expires-1, 0), maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrPathPrefix) {
		t.Errorf("got %v, want ErrPathPrefix", err)
	}
}

func TestVerifyRejectsIncompleteEnvelopeAsMalformed(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	at := time.Unix(v.Expires-1, 0)
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"signature removed", dropQueryParam(v.SignedURL, "x_ark_signature")},
		{"expiry removed", dropQueryParam(v.SignedURL, "x_ark_expires")},
		{"no envelope at all", v.URL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Verify(tc.url, at, maskedConds()...)
			if !errors.Is(err, bytearksigner.ErrMalformed) {
				t.Errorf("got %v, want ErrMalformed", err)
			}
		})
	}
}

// Envelope completeness is checked before expiry, so an unsigned URL is
// malformed rather than expired however late the clock is.
func TestVerifyChecksEnvelopeBeforeExpiry(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	err := s.Verify(v.URL, time.Unix(v.Expires+86400, 0), maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrMalformed) {
		t.Errorf("got %v, want ErrMalformed", err)
	}
}

// Expiry is checked before the signature, so an expired forgery reports
// ErrExpired and not ErrSignature.
func TestVerifyChecksExpiryBeforeSignature(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	err := s.Verify(tamperSignature(v.SignedURL), time.Unix(v.Expires+1, 0), maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}
}

// A masked condition supplied for a URL that never carried the corresponding
// key changes the string to sign, so it turns a valid URL into a rejection.
// Callers must pass masked conditions only when the key is present.
func TestVerifyRejectsMaskedConditionAbsentFromTheURL(t *testing.T) {
	s, v := verifySubject(t, plainSubjectVector)
	at := time.Unix(v.Expires-1, 0)
	if err := s.Verify(v.SignedURL, at); err != nil {
		t.Fatalf("test setup: subject must verify without conditions, got %v", err)
	}
	err := s.Verify(v.SignedURL, at, bytearksigner.ClientIP(ucClientIP))
	if !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

// Widening x_ark_path_prefix on the wire is caught by the signature, not by the
// prefix check, because the prefix is part of the string to sign.
func TestVerifyRejectsWidenedPathPrefixAsSignatureError(t *testing.T) {
	s, v := verifySubject(t, plainSubjectVector)
	widened := strings.Replace(v.SignedURL,
		"x_ark_path_prefix="+url.QueryEscape(ucPlaylistPrefix),
		"x_ark_path_prefix="+url.QueryEscape("/"), 1)
	if widened == v.SignedURL {
		t.Fatal("test setup: path prefix was not widened")
	}
	err := s.Verify(widened, time.Unix(v.Expires-1, 0))
	if !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsAlteredCustomConditionValue(t *testing.T) {
	s, v := verifySubject(t, plainSubjectVector)
	altered := strings.Replace(v.SignedURL,
		"x_ark_request_tags="+url.QueryEscape(ucRequestTags),
		"x_ark_request_tags="+url.QueryEscape("ark-strm-proj:aBcD1234,ark-strm-cid:OTHERVIDEO"), 1)
	if altered == v.SignedURL {
		t.Fatal("test setup: request tags were not altered")
	}
	err := s.Verify(altered, time.Unix(v.Expires-1, 0))
	if !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

// A zero at means "now", not "skip the expiry check"; every vector expires in
// the past, so a caller that forgets the clock still gets a real check.
func TestVerifyWithZeroTimeUsesTheCurrentClock(t *testing.T) {
	s, v := verifySubject(t, maskedSubjectVector)
	if time.Now().Unix() <= v.Expires {
		t.Skipf("reference vector %q has not expired yet", v.Name)
	}
	err := s.Verify(v.SignedURL, time.Time{}, maskedConds()...)
	if !errors.Is(err, bytearksigner.ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}
}

// -----------------------------------------------------------------------------
// Query-string surgery helpers. These operate on the raw signed URL on purpose:
// re-serialising through url.Values would rewrite bytes the signature covers.
// -----------------------------------------------------------------------------

// prependQueryParam inserts key=value at the front of the query string, for the
// case where a bare parameter has to come before the ark-v2 envelope.
func prependQueryParam(signedURL, key, value string) string {
	i := strings.IndexByte(signedURL, '?')
	if i < 0 {
		return signedURL + "?" + key + "=" + value
	}
	return signedURL[:i+1] + key + "=" + value + "&" + signedURL[i+1:]
}

// dropQueryParam removes the key=value segment named key from the query string.
func dropQueryParam(signedURL, key string) string {
	i := strings.IndexByte(signedURL, '?')
	if i < 0 {
		return signedURL
	}
	kept := make([]string, 0, 8)
	for _, seg := range strings.Split(signedURL[i+1:], "&") {
		if seg == key || strings.HasPrefix(seg, key+"=") {
			continue
		}
		kept = append(kept, seg)
	}
	return signedURL[:i+1] + strings.Join(kept, "&")
}

// tamperSignature flips the last character of x_ark_signature, leaving every
// other byte of the URL alone.
func tamperSignature(signedURL string) string {
	const key = "x_ark_signature="
	i := strings.Index(signedURL, key)
	if i < 0 {
		return signedURL
	}
	j := i + len(key)
	end := strings.IndexByte(signedURL[j:], '&')
	if end < 0 {
		end = len(signedURL)
	} else {
		end += j
	}
	if end == j {
		return signedURL
	}
	last := signedURL[end-1]
	flipped := byte('A')
	if last == 'A' {
		flipped = 'B'
	}
	return signedURL[:end-1] + string(flipped) + signedURL[end:]
}
