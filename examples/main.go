package main

import (
	"fmt"
	"time"

	ByteArkSignerSDK "github.com/byteark/byteark-sdk-go"
)

func main() {
	// Create signer options
	signerOptions := ByteArkSignerSDK.SignerOptions{
		AccessID:     "fleet-1320",
		AccessSecret: "2bpqxHOMUxVmkzA1",
	}

	// Create signer
	ByteArkSignerSDK.CreateSigner(signerOptions)

	// Create sign options
	signOptions := ByteArkSignerSDK.SignOptions{
		"path_prefix": "/live/",
	}

	// Sign given url
	signedURL, signError := ByteArkSignerSDK.Sign(
		"https://example.cdn.byteark.com/path/to/file.png",
		1514764800,
		signOptions,
	)

	if signError != nil {
		fmt.Printf("SignedURL: %s\n", signedURL)
	} else {
		panic(signError)
	}

	// Verify signedURL
	pass, verifyError := ByteArkSignerSDK.Verify(
		signedURL,
		int(time.Now().Unix()),
	)

	if pass {
		fmt.Println("Verify signedURL pass.")
	} else {
		panic(verifyError)
	}
}
