package bytearksigner

import (
	"errors"
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
func Sign(url string, expires int, options SignOptions) string {
	signer := CurrentSigner()

	return signer.Sign(url, expires, options)
}
