package bytearksigner_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

var (
	signedAt = time.Unix(1514764800-60, 0)
	expiry   = time.Unix(1514764800, 0)
)

func TestVerifyAcceptsOwnOutput(t *testing.T) {
	s := newTestSigner(t)
	signed, _ := s.Sign(testURL, expiry, bytearksigner.PathPrefix("/video-objects/"))
	if err := s.Verify(signed, signedAt); err != nil {
		t.Errorf("Verify = %v", err)
	}
}

// TestVerifyReferenceVectorsWithConditions verifies every reference vector.
// Masked options (client_ip, user_agent) and the method are not recoverable from
// the URL, so the verifier supplies them the way the CDN would. A couple of
// vectors exist only to exercise query serialisation and declare a path_prefix
// the signed URL's own path is not under (e.g. "/a b~c/ü/"); Verify correctly
// rejects those on the path-prefix check, and every other vector must verify
// clean.
func TestVerifyReferenceVectorsWithConditions(t *testing.T) {
	g := loadReference(t)
	for _, v := range g.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			id, secret := g.credentialsFor(v)
			s, _ := bytearksigner.New(id, secret, bytearksigner.WithSkipURLEncoding(v.SkipURLEncoding))
			err := s.Verify(v.SignedURL, time.Unix(v.Expires-1, 0), conditionsFromOptions(v.Options)...)
			if wantPathPrefixReject(t, v.SignedURL) {
				if !errors.Is(err, bytearksigner.ErrPathPrefix) {
					t.Errorf("Verify(%s) = %v, want ErrPathPrefix", v.Name, err)
				}
				return
			}
			if err != nil {
				t.Errorf("Verify(%s) = %v", v.Name, err)
			}
		})
	}
}

// wantPathPrefixReject reports whether signedURL declares an x_ark_path_prefix
// its own escaped path is not under — the same test Verify applies before it
// checks the signature.
func wantPathPrefixReject(t *testing.T, signedURL string) bool {
	t.Helper()
	u, err := url.Parse(signedURL)
	if err != nil {
		t.Fatal(err)
	}
	prefix := u.Query().Get("x_ark_path_prefix")
	return prefix != "" && !strings.HasPrefix(u.EscapedPath(), prefix)
}

func TestVerifyExpired(t *testing.T) {
	s := newTestSigner(t)
	signed, _ := s.Sign(testURL, expiry)
	if err := s.Verify(signed, expiry.Add(time.Second)); !errors.Is(err, bytearksigner.ErrExpired) {
		t.Errorf("err = %v want ErrExpired", err)
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	s := newTestSigner(t)
	signed, _ := s.Sign(testURL, expiry)
	tampered := strings.Replace(signed, "x_ark_signature=", "x_ark_signature=x", 1)
	if err := s.Verify(tampered, signedAt); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("err = %v want ErrSignature", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	signed, _ := newTestSigner(t).Sign(testURL, expiry)
	other, _ := bytearksigner.New(testAccessID, "wrong")
	if err := other.Verify(signed, signedAt); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("err = %v want ErrSignature", err)
	}
}

func TestVerifyPathOutsidePrefix(t *testing.T) {
	s := newTestSigner(t)
	signed, _ := s.Sign(testURL, expiry, bytearksigner.PathPrefix("/video-objects/QDuxJm02TYqJ/"))
	moved := strings.Replace(signed, "/video-objects/QDuxJm02TYqJ/playlist.m3u8", "/video-objects/OTHER/playlist.m3u8", 1)
	if err := s.Verify(moved, signedAt); !errors.Is(err, bytearksigner.ErrPathPrefix) {
		t.Errorf("err = %v want ErrPathPrefix", err)
	}
}

func TestVerifyMaskedClientIPNeedsCallerValue(t *testing.T) {
	s := newTestSigner(t)
	signed, _ := s.Sign(testURL, expiry, bytearksigner.ClientIP("1.2.3.4"))
	if err := s.Verify(signed, signedAt); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("without client ip: err = %v want ErrSignature", err)
	}
	if err := s.Verify(signed, signedAt, bytearksigner.ClientIP("1.2.3.4")); err != nil {
		t.Errorf("with client ip: err = %v", err)
	}
	if err := s.Verify(signed, signedAt, bytearksigner.ClientIP("9.9.9.9")); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("wrong client ip: err = %v want ErrSignature", err)
	}
}

// TestVerifyAppendedBareParamStillValid covers the CDN behaviour that only
// x_ark_* keys participate in the signature.
func TestVerifyAppendedBareParamStillValid(t *testing.T) {
	s := newTestSigner(t)
	signed, _ := s.Sign(testURL, expiry)
	if err := s.Verify(signed+"&resolution=720p", signedAt); err != nil {
		t.Errorf("bare param broke verification: %v", err)
	}
	if err := s.Verify(signed+"&x_ark_extra=1", signedAt); !errors.Is(err, bytearksigner.ErrSignature) {
		t.Errorf("x_ark_ param should break verification, got %v", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	s := newTestSigner(t)
	for _, raw := range []string{"://bad", testURL, testURL + "?x_ark_expires=abc&x_ark_signature=x"} {
		if err := s.Verify(raw, signedAt); !errors.Is(err, bytearksigner.ErrMalformed) {
			t.Errorf("Verify(%q) = %v want ErrMalformed", raw, err)
		}
	}
}
