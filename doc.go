// Package bytearksigner creates, verifies and renews ByteArk signed URLs (ark-v2).
//
// Terms used throughout the package:
//
//   - Policy: the set of constraints a URL was signed with. It travels on the
//     URL as x_ark_<key> query parameters and is covered by the signature, so
//     changing any part of it invalidates the URL.
//   - Condition: one policy entry, added by passing a Condition value to Sign
//     (PathPrefix, ClientIP, UserAgent, Method, Custom). Keys are canonical:
//     lower-case, with '-' replaced by '_'.
//   - Envelope: the four parameters that identify and authenticate the URL
//     (x_ark_access_id, x_ark_auth_type, x_ark_expires, x_ark_signature).
//     They sit outside the policy.
//   - Masked condition: ClientIP and UserAgent are signed with their real
//     values but written to the URL as x_ark_client_ip=1 and x_ark_user_agent=1.
//
// Construct one Signer per credential and share it freely; it is immutable
// after construction and safe for concurrent use.
//
//	signer, err := bytearksigner.New("ACCESS_ID", "ACCESS_SECRET")
//	signedURL, err := signer.Sign(
//		"https://example.cdn.byteark.com/path/to/file.m3u8",
//		time.Now().Add(15*time.Minute),
//		bytearksigner.PathPrefix("/path/to/"),
//	)
//
// # How the policy reaches the verifier
//
// Every policy entry is carried as x_ark_<key>, with two exceptions. Method is
// signed but absent from the URL, so a verifier takes the method from the
// request itself. PathPrefix stands in for the URL path inside the signature,
// which makes one signature valid for every path under the prefix. Masked
// conditions arrive as the literal 1, so Verify takes the real request values
// as conditions for URLs signed with them. Query parameters outside the x_ark_
// prefix are neither signed nor checked.
//
// # Renewing a signed URL
//
// Renew issues a fresh expiry and signature for an already-signed URL, keeps
// its policy byte-for-byte, and does so only after the existing signature
// verifies with this Signer's secret. Reissue signs a URL again with a changed
// policy and skips that check, so it belongs behind trusted input only.
package bytearksigner
