package bytearksigner

import (
	"errors"
	"fmt"
)

// CreateSigner create new signer for further use.
func CreateSigner(options SignerOptions) error {
	signer := CurrentSigner()

	signer.SetAccessID(options.AccessID)

	if options.AccessSecret == "" {
		return errors.New("AccessSecret is required")
	}
	signer.SetAccessSecret(options.AccessSecret)

	if options.DefaultAge != 0 {
		signer.SetDefaultAge(options.DefaultAge)
	}

	return nil
}

// Sign exact sign function to call
func Sign(url string, expires int, options SignOptions) (string, error) {
	signer := CurrentSigner()

	return signer.Sign(url, expires, options)
}

// Verify signedurl
func Verify(url string, now int) (bool, error) {
	signer := CurrentSigner()

	bo, err := signer.Verify(url, now)

	if !bo {
		fmt.Printf("%e", err)
	}

	return bo, err
}
