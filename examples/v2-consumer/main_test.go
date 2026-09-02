package main

import "testing"

// Reference URL produced by the reference implementation, the ByteArk PHP SDK
// (see testdata/reference_vectors.json, vector "path_prefix").
const wantSigned = "http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8?x_ark_access_id=2Aj6Wkge4hi1ZYLp0DBG&x_ark_auth_type=ark-v2&x_ark_expires=1514764800&x_ark_path_prefix=%2Fvideo-objects%2FQDuxJm02TYqJ%2F&x_ark_signature=334wInm0jKfC6LCm23zndA"

func TestPlaylistURLMatchesReference(t *testing.T) {
	signer := mustSigner()
	got, err := playlistURL(signer, "/video-objects/QDuxJm02TYqJ/")
	if err != nil {
		t.Fatal(err)
	}
	if got != wantSigned {
		t.Errorf("\n got %s\nwant %s", got, wantSigned)
	}
}
