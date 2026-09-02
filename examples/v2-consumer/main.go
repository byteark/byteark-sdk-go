// Sample v2 consumer used by the migration acceptance demo. It exercises the
// instance-based v2 API (New, Signer.Sign) — no global singleton.
package main

import (
	"fmt"
	"time"

	bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

func mustSigner() *bytearksigner.Signer {
	// v1 set SkipURLEncoding(false), i.e. URL encoding ON; that is v2's default,
	// so no WithSkipURLEncoding option is needed to keep output byte-identical.
	signer, err := bytearksigner.New(
		"2Aj6Wkge4hi1ZYLp0DBG",
		"31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7",
	)
	if err != nil {
		panic(err)
	}
	return signer
}

func playlistURL(signer *bytearksigner.Signer, prefix string) (string, error) {
	return signer.Sign(
		"http://inox.qoder.byteark.com/video-objects/QDuxJm02TYqJ/playlist.m3u8",
		time.Unix(1514764800, 0),
		bytearksigner.PathPrefix(prefix),
	)
}

func main() {
	signer := mustSigner()
	u, err := playlistURL(signer, "/video-objects/QDuxJm02TYqJ/")
	if err != nil {
		panic(err)
	}
	fmt.Println(u)
}
