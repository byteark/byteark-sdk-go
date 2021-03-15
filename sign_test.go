package bytearksigner

import (
	"testing"
)

func TestSignedURLValidity(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG&x_ark_auth_type=ark-v2&x_ark_expires=1514764800&x_ark_signature=cLwtn96a-YPY7jt8ZKSf_Q"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL")
	}
}

func TestSignedURLValidityTwice(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{}

	firstSignedURL, firstErr := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if firstErr != nil {
		t.Errorf("Got error from signer.Sign on the first sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG&x_ark_auth_type=ark-v2&x_ark_expires=1514764800&x_ark_signature=cLwtn96a-YPY7jt8ZKSf_Q"

	if firstSignedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL")
	}

	secondSignedURL, secondErr := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if secondErr != nil {
		t.Errorf("Got error from signer.Sign on the second sign.")
	}

	if secondSignedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL")
	}
}

func TestSignedURLWithOtherHTTPMethod(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{
		"method": "HEAD",
	}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG&x_ark_auth_type=ark-v2&x_ark_expires=1514764800&x_ark_signature=QULE8DQ08f8fhFC-1gDUWQ"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL")
	}
}

func TestSignedURLWithPathPrefix(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{
		"path_prefix": "/video-objects/QDuxJm02TYqJ/",
	}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	expectedSignedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	expectedSignedURL += "&x_ark_auth_type=ark-v2"
	expectedSignedURL += "&x_ark_expires=1514764800"
	expectedSignedURL += "&x_ark_path_prefix=%2Fvideo-objects%2FQDuxJm02TYqJ%2F"
	expectedSignedURL += "&x_ark_signature=334wInm0jKfC6LCm23zndA"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL")
	}
}

func TestSignedURLWithClientIP(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{
		"client_ip": "103.253.132.65",
	}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	expectedSignedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	expectedSignedURL += "&x_ark_auth_type=ark-v2"
	expectedSignedURL += "&x_ark_client_ip=1"
	expectedSignedURL += "&x_ark_expires=1514764800"
	expectedSignedURL += "&x_ark_signature=Gr9T_ZdHDy8l8CCPxpFjNg"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL\nGot: %s\nExpect: %s", signedURL, expectedSignedURL)
	}
}

func TestSignedURLWithDashedClientIP(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{
		"client-ip": "103.253.132.65",
	}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	expectedSignedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	expectedSignedURL += "&x_ark_auth_type=ark-v2"
	expectedSignedURL += "&x_ark_client_ip=1"
	expectedSignedURL += "&x_ark_expires=1514764800"
	expectedSignedURL += "&x_ark_signature=Gr9T_ZdHDy8l8CCPxpFjNg"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL\nGot: %s\nExpect: %s", signedURL, expectedSignedURL)
	}
}

func TestSignedURLWithClietIPAndUserAgent(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) "
	userAgent += "AppleWebKit/537.36 (KHTML, like Gecko) "
	userAgent += "Chrome/58.0.3029.68 Safari/537.36"

	signOption := SignOptions{
		"client_ip":  "103.253.132.65",
		"user_agent": userAgent,
	}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	expectedSignedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	expectedSignedURL += "&x_ark_auth_type=ark-v2"
	expectedSignedURL += "&x_ark_client_ip=1"
	expectedSignedURL += "&x_ark_expires=1514764800"
	expectedSignedURL += "&x_ark_signature=yYFkwZolbxCarOLHuKjD7w"
	expectedSignedURL += "&x_ark_user_agent=1"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL\nGot: %s\nExpect: %s", signedURL, expectedSignedURL)
	}
}

func TestSignedURLWithClietIPAndPathPrefix(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) "
	userAgent += "AppleWebKit/537.36 (KHTML, like Gecko) "
	userAgent += "Chrome/58.0.3029.68 Safari/537.36"

	signOption := SignOptions{
		"client-ip":   "103.253.132.65",
		"path_prefix": "/video-objects/QDuxJm02TYqJ/",
	}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	expectedSignedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	expectedSignedURL += "&x_ark_auth_type=ark-v2"
	expectedSignedURL += "&x_ark_client_ip=1"
	expectedSignedURL += "&x_ark_expires=1514764800"
	expectedSignedURL += "&x_ark_path_prefix=%2Fvideo-objects%2FQDuxJm02TYqJ%2F"
	expectedSignedURL += "&x_ark_signature=2bkwVFSu6CzW7KmzXkwDbA"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL\nGot: %s\nExpect: %s", signedURL, expectedSignedURL)
	}
}

func TestValidateSignedURL(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	signedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	signedURL += "&x_ark_auth_type=ark-v2"
	signedURL += "&x_ark_expires=1514764800"
	signedURL += "&x_ark_signature=cLwtn96a-YPY7jt8ZKSf_Q"

	bo, verifyErr := signer.Verify(signedURL, 1514764700)

	if !bo {
		t.Errorf("Verfiy failed, %s", verifyErr)
	}
}

func TestValidateSignedURLFail(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	signedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	signedURL += "&x_ark_auth_type=ark-v2"
	signedURL += "&x_ark_expires=1514764800"
	signedURL += "&x_ark_signature=cLwtn96a-YPY7jt8ZKSf_R"

	bo, verifyErr := signer.Verify(signedURL, 1514764700)

	if bo {
		t.Errorf("Verfiy pass, it should faile, %s", verifyErr)
	}
}

func TestInvalidExpireSignedURL(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8"
	signedURL += "?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG"
	signedURL += "&x_ark_auth_type=ark-v2"
	signedURL += "&x_ark_expires=1514764800"
	signedURL += "&x_ark_signature=cLwtn96a-YPY7jt8ZKSf_Q"

	bo, verifyErr := signer.Verify(signedURL, 1514764900)

	if bo {
		t.Errorf("Verfiy pass, it should faile, %s", verifyErr)
	}
}

func TestSignAfterChangeAccessIDAndSecret(t *testing.T) {
	signer := CurrentSigner()

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signOption := SignOptions{}

	signedURL, err := signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from first signer.Sign")
	}

	expectedSignedURL := "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG&x_ark_auth_type=ark-v2&x_ark_expires=1514764800&x_ark_signature=cLwtn96a-YPY7jt8ZKSf_Q"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL before change access ID and Secret")
	}

	signer.SetAccessID("2Aj6Wkge4hi1ZYLp0DBG")
	signer.SetAccessSecret("new31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7")

	signedURL, err = signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		1514764800,
		signOption,
	)

	if err != nil {
		t.Errorf("Got error from second signer.Sign")
	}

	expectedSignedURL = "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG&x_ark_auth_type=ark-v2&x_ark_expires=1514764800&x_ark_signature=Aig2HEXevVEeF8VwbnlMSg"

	if signedURL != expectedSignedURL {
		t.Errorf("Mismacth signedURL before change access ID and Secret")
	}
}
