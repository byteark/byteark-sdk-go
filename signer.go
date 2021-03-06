package bytearksigner

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	URL "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pasztorpisti/qs"
)

// Signer struct for Signer class.
type Signer struct {
	AccessID        string
	AccessSecret    string
	DefaultAge      int
	SkipURLEncoding bool
}

// SignerOptions is option on creating new signer
type SignerOptions struct {
	AccessID     string
	AccessSecret string
	DefaultAge   int
}

// SignOptions for query params inside signedURL
type SignOptions map[string]string

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
func (s Signer) Sign(url string, expires int, options SignOptions) (string, error) {
	if expires == 0 {
		defaultAge, _ := time.ParseDuration(fmt.Sprintf("%ds", s.GetDefaultAge()))
		expires = int(time.Now().Add(defaultAge).Unix())
	}

	queryParams, marshalError := qs.Marshal(makeQueryParams(s, url, expires, options))

	if marshalError != nil {
		return "", marshalError
	}

	return fmt.Sprintf("%s?%s", url, queryParams), nil
}

// Verify signed url
func (s Signer) Verify(url string, now int) (bool, error) {
	if now == 0 {
		now = int(time.Now().Unix())
	}

	parsedURL, _ := URL.Parse(url)
	parsedURLWithoutQuery := fmt.Sprintf("%s://%s%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Port(), parsedURL.Path)
	parsedQuery := parsedURL.Query()

	parsedExpires, _ := strconv.Atoi(parsedQuery.Get("x_ark_expires"))
	if parsedExpires < now {
		return false, errors.New("Signed URL is expired")
	}

	if parsedQuery.Get("x_ark_path_prefix") != "" && !strings.HasPrefix(parsedURL.Path, parsedQuery.Get("x_ark_path_prefix")) {
		return false, errors.New("Invalid signed URL condition")
	}

	var options = make(map[string]string)
	for key := range parsedQuery {
		if shouldQueryExistsInOptions(key) {
			options[trimKey(key)] = parsedQuery.Get(key)
		}
	}

	expectedSignature := makeSignature(s, parsedURLWithoutQuery, parsedExpires, options)

	if expectedSignature != parsedQuery.Get("x_ark_signature") {
		return false, errors.New("Invalid signed URL")
	}

	return true, nil
}

// SetAccessID set AccessID to signer
func (s *Signer) SetAccessID(accessID string) {
	s.AccessID = accessID
}

// SetAccessSecret set AccessSecret to signer
func (s *Signer) SetAccessSecret(accessSecret string) {
	s.AccessSecret = accessSecret
}

// SetDefaultAge set DefaultAge as assign value to signer
func (s *Signer) SetDefaultAge(defaultAge int) {
	s.DefaultAge = defaultAge
}

// SetSkipURLEncoding set SkipURLEncoding to signer with input value
func (s *Signer) SetSkipURLEncoding(skipURLEncoding bool) {
	s.SkipURLEncoding = skipURLEncoding
}

// GetDefaultAge return signer current default age
func (s *Signer) GetDefaultAge() int {
	return s.DefaultAge
}

func makeQueryParams(signer Signer, url string, expires int, options SignOptions) map[string]string {
	options = validateSignOptions(&options)

	var queryParams = make(map[string]string)

	queryParams["x_ark_access_id"] = signer.AccessID
	queryParams["x_ark_auth_type"] = "ark-v2"
	queryParams["x_ark_expires"] = strconv.Itoa(expires)
	queryParams["x_ark_signature"] = makeSignature(signer, url, expires, options)

	for key, value := range options {
		if shouldOptionsExistsInQuery(key) {
			if shouldOptionValueExistsInQuery(key) {
				queryParams[changeKeyToXArkKey(key)] = value
			} else {
				queryParams[changeKeyToXArkKey(key)] = "1"
			}
		}
	}

	keys := make([]string, len(queryParams))

	for k := range queryParams {
		keys = append(keys, k)
	}

	return queryParams
}

func validateSignOptions(s *SignOptions) SignOptions {
	ns := make(map[string]string)
	for key, value := range *s {
		validKey := strings.ReplaceAll(key, "-", "_")
		ns[validKey] = value
	}
	return ns
}

func changeKeyToXArkKey(key string) string {
	if strings.HasPrefix(key, "x_ark_") {
		return key
	}
	key = strings.ReplaceAll(key, "-", "_")
	return fmt.Sprintf("x_ark_%s", key)
}

func shouldOptionsExistsInQuery(optionKey string) bool {
	return optionKey != "method"
}

func shouldOptionValueExistsInQuery(key string) bool {
	return key != "client_ip" && key != "client-ip" && key != "user_agent"
}

func makeSignature(signer Signer, url string, expires int, options SignOptions) string {
	stringToSign := makeStringToSign(signer, url, expires, options)

	hasher := md5.New()
	hasher.Write([]byte(stringToSign))
	hashed := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	hashed = strings.ReplaceAll(hashed, "+", "-")
	hashed = strings.ReplaceAll(hashed, "/", "_")
	hashed = strings.TrimRight(hashed, "=")

	return hashed
}

func makeStringToSign(signer Signer, url string, expires int, options SignOptions) string {
	urlComponents, _ := URL.Parse(url)

	var lineToSign []string

	if options["method"] != "" {
		lineToSign = append(lineToSign, options["method"])
	} else {
		lineToSign = append(lineToSign, "GET")
	}

	lineToSign = append(lineToSign, urlComponents.Host)

	if options["path_prefix"] != "" {
		lineToSign = append(lineToSign, options["path_prefix"])
	} else {
		lineToSign = append(lineToSign, urlComponents.Path)
	}

	lineToSign = append(lineToSign, makeCustomPolicyLines(options)...)
	lineToSign = append(lineToSign, strconv.Itoa(expires))
	lineToSign = append(lineToSign, signer.AccessSecret)

	return strings.Join(lineToSign, "\n")
}

func makeCustomPolicyLines(options SignOptions) []string {
	var op = make(map[string]string)
	for key, value := range options {
		if shouldOptionExistsInCustomPolicyLine(key) {
			op[key] = value
		}
	}

	var opKeys []string
	for k := range op {
		opKeys = append(opKeys, k)
	}

	sort.Strings(opKeys)

	var st []string

	for _, k := range opKeys {
		st = append(st, fmt.Sprintf("%s:%s", k, op[k]))
	}

	return st
}

func shouldOptionExistsInCustomPolicyLine(key string) bool {
	return key != "method" && key != "path_prefix"
}

func shouldQueryExistsInOptions(key string) bool {
	return strings.HasPrefix(key, "x_ark_") && key != "x_ark_access_id" && key != "x_ark_auth_type" && key != "x_ark_expires" && key != "x_ark_signature"
}

func trimKey(key string) string {
	if strings.HasPrefix(key, "x_ark_") {
		return strings.TrimPrefix(key, "x_ark_")
	}
	return key
}
