package bytearksigner_test

import (
	"crypto/sha256"
	"errors"
	"hash"
	"strings"
	"sync"
	"testing"
	"time"

	bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

const (
	testAccessID = "2Aj6Wkge4hi1ZYLp0DBG"
	testSecret   = "31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7"
	testURL      = "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
)

func newTestSigner(t *testing.T, opts ...bytearksigner.Option) *bytearksigner.Signer {
	t.Helper()
	s, err := bytearksigner.New(testAccessID, testSecret, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewRequiresSecret(t *testing.T) {
	_, err := bytearksigner.New("id", "")
	if !errors.Is(err, bytearksigner.ErrMissingSecret) {
		t.Errorf("err = %v want ErrMissingSecret", err)
	}
}

func TestNewAllowsEmptyAccessID(t *testing.T) {
	if _, err := bytearksigner.New("", testSecret); err != nil {
		t.Errorf("unexpected err %v", err)
	}
}

func TestSignRejectsURLWithQuery(t *testing.T) {
	_, err := newTestSigner(t).Sign(testURL+"?a=b", time.Unix(1514764800, 0))
	if !errors.Is(err, bytearksigner.ErrURLHasQuery) {
		t.Errorf("err = %v want ErrURLHasQuery", err)
	}
}

func TestSignZeroExpiresUsesDefaultAge(t *testing.T) {
	s := newTestSigner(t, bytearksigner.WithDefaultAge(60*time.Second))
	before := time.Now().Add(60 * time.Second).Unix()
	signed, err := s.Sign(testURL, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(60 * time.Second).Unix()
	var exp int64
	for _, kv := range strings.Split(strings.SplitN(signed, "?", 2)[1], "&") {
		if strings.HasPrefix(kv, "x_ark_expires=") {
			for _, c := range strings.TrimPrefix(kv, "x_ark_expires=") {
				exp = exp*10 + int64(c-'0')
			}
		}
	}
	if exp < before || exp > after {
		t.Errorf("expires %d not within [%d,%d]", exp, before, after)
	}
}

func TestDefaultAgeIs900Seconds(t *testing.T) {
	if bytearksigner.DefaultAge != 900*time.Second {
		t.Errorf("DefaultAge = %v", bytearksigner.DefaultAge)
	}
}

func TestWithHasherChangesSignature(t *testing.T) {
	md5Signed, _ := newTestSigner(t).Sign(testURL, time.Unix(1514764800, 0))
	shaSigned, err := newTestSigner(t, bytearksigner.WithHasher(func() hash.Hash { return sha256.New() })).
		Sign(testURL, time.Unix(1514764800, 0))
	if err != nil {
		t.Fatal(err)
	}
	if md5Signed == shaSigned {
		t.Error("expected different signatures for different hashers")
	}
	if !strings.Contains(md5Signed, "x_ark_signature=cLwtn96a-YPY7jt8ZKSf_Q") {
		t.Errorf("md5 signature drift: %s", md5Signed)
	}
}

func TestSignDoesNotMutateSignerAcrossCalls(t *testing.T) {
	s := newTestSigner(t)
	a, _ := s.Sign(testURL, time.Unix(1514764800, 0), bytearksigner.PathPrefix("/video-objects/"))
	b, _ := s.Sign(testURL, time.Unix(1514764800, 0))
	if strings.Contains(b, "x_ark_path_prefix") {
		t.Errorf("condition leaked into later call: %s", b)
	}
	if a == b {
		t.Error("expected different URLs")
	}
}

func TestConcurrentSignersWithDifferentCredentials(t *testing.T) {
	s1 := newTestSigner(t)
	s2, err := bytearksigner.New("other", "othersecret")
	if err != nil {
		t.Fatal(err)
	}
	want1, _ := s1.Sign(testURL, time.Unix(1514764800, 0))
	want2, _ := s2.Sign(testURL, time.Unix(1514764800, 0))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got, _ := s1.Sign(testURL, time.Unix(1514764800, 0)); got != want1 {
				t.Errorf("s1 drift: %s", got)
			}
		}()
		go func() {
			defer wg.Done()
			if got, _ := s2.Sign(testURL, time.Unix(1514764800, 0)); got != want2 {
				t.Errorf("s2 drift: %s", got)
			}
		}()
	}
	wg.Wait()
}
