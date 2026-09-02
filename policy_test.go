package bytearksigner

import "testing"

func TestCanonicalKey(t *testing.T) {
	cases := map[string]string{
		"client_ip": "client_ip", "client-ip": "client_ip", "Client-IP": "client_ip",
		"USER_AGENT": "user_agent", "path_prefix": "path_prefix", "viewer-group": "viewer_group",
	}
	for in, want := range cases {
		if got := canonicalKey(in); got != want {
			t.Errorf("canonicalKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewPolicyAppliesConditionsWithCanonicalKeys(t *testing.T) {
	p := newPolicy([]Condition{
		PathPrefix("/live/"), ClientIP("1.2.3.4"), UserAgent("ua"), Method("put"), Custom("Viewer-Group", "premium"),
	})
	want := policy{"path_prefix": "/live/", "client_ip": "1.2.3.4", "user_agent": "ua", "method": "PUT", "viewer_group": "premium"}
	if len(p) != len(want) {
		t.Fatalf("got %v want %v", p, want)
	}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("p[%q] = %q want %q", k, p[k], v)
		}
	}
}

func TestPolicyMethodDefaultsToGET(t *testing.T) {
	if got := newPolicy(nil).method(); got != "GET" {
		t.Errorf("method() = %q want GET", got)
	}
}

func TestEmptyValuesAreIgnored(t *testing.T) {
	p := newPolicy([]Condition{Custom("x", ""), PathPrefix(""), Method("")})
	if len(p) != 0 {
		t.Errorf("expected empty policy, got %v", p)
	}
}
