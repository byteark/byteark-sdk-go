package bytearksigner

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"
)

// Signer struct for class.
type Signer struct {
	AccessID        string
	AccessSecret    string
	DefaultAge      int64
	SkipURLEncoding bool
}

// SignerOptions is option on creating new signer
type SignerOptions struct {
	AccessID     string
	AccessSecret string
	DefaultAge   int64
}

// SignOptions is option for signing
type SignOptions struct {
	AccessID string
	AuthType string
	Expires  int64
}

type signQuery struct {
	AccessID  string `qs:"x_ark_access_id"`
	AuthType  string `qs:"x_ark_auth_type"`
	Expires   int64  `qs:"x_ark_expires"`
	Signature string `qs:"x_ark_signature"`
}

var currentSigner = newSigner()

func newSigner() *Signer {
	signer := Signer{
		DefaultAge:      900,
		SkipURLEncoding: true,
	}

	return &signer
}

// CurrentSigner return already create currentSigner
func CurrentSigner() *Signer {
	return currentSigner
}

// Sign is main feature function for signer.
func (s Signer) Sign(url string, expires int64, signOption SignOptions) string {
	if expires == 0 {
		defaultAge, _ := time.ParseDuration(fmt.Sprintf("%ds", s.GetDefaultAge()))
		expires = time.Now().Add(defaultAge).Unix()
	}

	return fmt.Sprintf("%s?", url) // s.AccessID + s.AccessSecret
}

// SetAccessID set AccessID to signer
func (s *Signer) SetAccessID(accessID string) {
	s.AccessID = accessID
}

// SetAccessSecret set AccessSecret to signer
func (s *Signer) SetAccessSecret(accessSecret string) {
	s.AccessID = accessSecret
}

// SetDefaultAge set DefaultAge as assign value to signer
func (s *Signer) SetDefaultAge(defaultAge int64) {
	s.DefaultAge = defaultAge
}

// SetSkipURLEncoding set SkipURLEncoding to signer with input value
func (s *Signer) SetSkipURLEncoding(skipURLEncoding bool) {
	s.SkipURLEncoding = skipURLEncoding
}

// GetDefaultAge return signer current default age
func (s *Signer) GetDefaultAge() int64 {
	return s.DefaultAge
}

func makeQueryString(url string, expires int64, signOptions SignOptions) string {

}

func makeSignature(url string, expires int64, options SignOptions) string {
	stringToSign := makeStringToSign(url, expires, options)
}

// makeStringToSign(url, expires, options) {
//         const urlComponents = urlParse(url);

//         let linesToSign = [];
//         linesToSign.push(options.method ? options.method : 'GET');
//         linesToSign.push(urlComponents.host);
//         linesToSign.push(options.path_prefix ? options.path_prefix : urlComponents.pathname);
//         linesToSign = linesToSign.concat(this.makeCustomPolicyLines(options));
//         linesToSign.push(expires);
//         linesToSign.push(this.options.access_secret);

//         return linesToSign.join('\n');
//     }

func makeStringToSign(url string, expires int64, options SignOptions) string {

}

func hashMD5(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

// makeSignature(url, expires, options) {
//         const stringToSign = this.makeStringToSign(url, expires, options);

//         const hasher = crypto.createHash('md5');
//         hasher.update(stringToSign);

//         return hasher.digest('base64')
//             .replace(/\+/g, '-')
//             .replace(/\//g, '_')
//             .replace(/=+$/, '');
//     }
