package bytearksigner

import (
	"crypto/md5"
	"hash"
	"net/url"
	"testing"
)

const testSecret = "31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7"

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestStringToSignLayout(t *testing.T) {
	u := mustParse(t, "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8")
	p := newPolicy([]Condition{Method("post"), ClientIP("1.2.3.4"), Custom("viewer_group", "vip"), PathPrefix("/video-objects/")})
	got := stringToSign(u, 1514764800, p, testSecret)
	want := "POST\ninox.qoder.byteark.com\n/video-objects/\nclient_ip:1.2.3.4\nviewer_group:vip\n1514764800\n" + testSecret
	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

// TestStringToSignKeepsPort: host:port is signed as written, port included
// (reference vector host_with_port).
func TestStringToSignKeepsPort(t *testing.T) {
	u := mustParse(t, "http://inox.qoder.byteark.com:8080/x/playlist.m3u8")
	got := stringToSign(u, 1, newPolicy(nil), "s")
	if got != "GET\ninox.qoder.byteark.com:8080\n/x/playlist.m3u8\n1\ns" {
		t.Errorf("got %q", got)
	}
}

func TestSignatureMatchesKnownVector(t *testing.T) {
	u := mustParse(t, "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8")
	p := newPolicy([]Condition{PathPrefix("/video-objects/QDuxJm02TYqJ/")})
	sig := signature(func() hash.Hash { return md5.New() }, stringToSign(u, 1514764800, p, testSecret))
	if sig != "334wInm0jKfC6LCm23zndA" {
		t.Errorf("signature = %q", sig)
	}
}

func TestQueryParamsMasking(t *testing.T) {
	p := newPolicy([]Condition{Method("POST"), ClientIP("1.2.3.4"), UserAgent("ua"), PathPrefix("/live/"), Custom("viewer_group", "vip")})
	got := queryParams("ID", 5, "SIG", p)
	want := map[string]string{
		"x_ark_access_id": "ID", "x_ark_auth_type": "ark-v2", "x_ark_expires": "5", "x_ark_signature": "SIG",
		"x_ark_client_ip": "1", "x_ark_user_agent": "1", "x_ark_path_prefix": "/live/", "x_ark_viewer_group": "vip",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q want %q", k, got[k], v)
		}
	}
}

func TestFormEncode(t *testing.T) {
	if got := formEncode("/a b~c/ü/"); got != "%2Fa+b%7Ec%2F%C3%BC%2F" {
		t.Errorf("got %q", got)
	}
}

func TestSerializeQuerySortedAndEncoded(t *testing.T) {
	params := map[string]string{"x_ark_path_prefix": "/a b~c/", "x_ark_access_id": "ID"}
	if got := serializeQuery(params, false); got != "x_ark_access_id=ID&x_ark_path_prefix=%2Fa+b%7Ec%2F" {
		t.Errorf("encoded: %q", got)
	}
	if got := serializeQuery(params, true); got != "x_ark_access_id=ID&x_ark_path_prefix=/a b~c/" {
		t.Errorf("raw: %q", got)
	}
}
