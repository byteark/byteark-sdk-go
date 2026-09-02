package bytearksigner_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	bytearksigner "github.com/byteark/byteark-sdk-go/v2"
)

type referenceFile struct {
	AccessID     string   `json:"access_id"`
	AccessSecret string   `json:"access_secret"`
	Vectors      []vector `json:"vectors"`
}

type vector struct {
	Name            string            `json:"name"`
	URL             string            `json:"url"`
	Expires         int64             `json:"expires"`
	Options         map[string]string `json:"options"`
	SkipURLEncoding bool              `json:"skip_url_encoding"`
	SignedURL       string            `json:"signed_url"`
	// AccessID and AccessSecret override the file-level credential pair for a
	// single vector (the key-rotation vectors). Empty means "use the file-level pair".
	AccessID     string `json:"access_id"`
	AccessSecret string `json:"access_secret"`
}

// credentialsFor returns the credential pair v was generated with.
func (g referenceFile) credentialsFor(v vector) (accessID, accessSecret string) {
	if v.AccessSecret != "" {
		return v.AccessID, v.AccessSecret
	}
	return g.AccessID, g.AccessSecret
}

func loadReference(t *testing.T) referenceFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/reference_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var g referenceFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Vectors) == 0 {
		t.Fatal("no reference vectors loaded")
	}
	return g
}

// conditionsFromOptions maps a reference vector's raw option keys onto v2
// Conditions through the Custom escape hatch only, so the harness exercises key
// canonicalisation on the keys exactly as the vector records them.
func conditionsFromOptions(opts map[string]string) []bytearksigner.Condition {
	conds := make([]bytearksigner.Condition, 0, len(opts))
	for k, v := range opts {
		conds = append(conds, bytearksigner.Custom(k, v))
	}
	return conds
}

func TestReferenceVectors(t *testing.T) {
	g := loadReference(t)
	for _, v := range g.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			id, secret := g.credentialsFor(v)
			s, err := bytearksigner.New(id, secret,
				bytearksigner.WithSkipURLEncoding(v.SkipURLEncoding))
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Sign(v.URL, time.Unix(v.Expires, 0), conditionsFromOptions(v.Options)...)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if got != v.SignedURL {
				t.Errorf("wire drift\n got: %s\nwant: %s", got, v.SignedURL)
			}
		})
	}
}
