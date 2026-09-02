package bytearksigner

import "errors"

var (
	// ErrMissingSecret is returned by New when accessSecret is empty.
	ErrMissingSecret = errors.New("bytearksigner: access secret is required")
	// ErrURLHasQuery is returned by Sign when the URL already has a query string.
	ErrURLHasQuery = errors.New("bytearksigner: URL to sign must not contain a query string")
	// ErrMalformed is returned by Verify when the URL is unparsable or lacks ark-v2 fields.
	ErrMalformed = errors.New("bytearksigner: malformed signed URL")
	// ErrExpired is returned by Verify when x_ark_expires is in the past.
	ErrExpired = errors.New("bytearksigner: signed URL is expired")
	// ErrPathPrefix is returned by Verify when the URL path is outside x_ark_path_prefix.
	ErrPathPrefix = errors.New("bytearksigner: URL path does not match signed path prefix")
	// ErrSignature is returned by Verify when x_ark_signature does not match.
	ErrSignature = errors.New("bytearksigner: invalid signature")
	// ErrNotSigned is returned by Renew when the URL carries no complete ark-v2 envelope.
	ErrNotSigned = errors.New("bytearksigner: URL is not an ark-v2 signed URL")
	// ErrMaskedValue is returned by Renew and Reissue when a masked condition is
	// left at its wire placeholder instead of the real value.
	ErrMaskedValue = errors.New("bytearksigner: masked condition needs its real value")
	// ErrPolicyChange is returned by Renew when a condition would change the signed policy.
	ErrPolicyChange = errors.New("bytearksigner: Renew cannot change the signed policy")
)
