package token_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rorylshanks/ch-podauth/internal/testutil"
	"github.com/rorylshanks/ch-podauth/internal/token"
)

// TestRefreshRejectsForeignJWKSURI ensures a tampered discovery document cannot
// redirect the JWKS fetch to a host other than the configured issuer.
func TestRefreshRejectsForeignJWKSURI(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   server.URL,
				"jwks_uri": "http://attacker.example.com/keys",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	validator, err := token.NewOIDCValidator(token.OIDCValidatorConfig{
		Issuer:      server.URL,
		Audience:    "clickhouse-auth",
		JWKSTTL:     time.Hour,
		HTTPTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = validator.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "jwks_uri") {
		t.Fatalf("Refresh() error = %v, want jwks_uri host rejection", err)
	}
}

// TestRefreshSkipsUnparseableKeys ensures a single malformed key in the JWKS
// does not break validation for the remaining good keys.
func TestRefreshSkipsUnparseableKeys(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			// A bad EC key (unsupported curve) alongside a good RSA key.
			good := testutil.JWKS(t, key)
			var parsed struct {
				Keys []json.RawMessage `json:"keys"`
			}
			if err := json.Unmarshal(good, &parsed); err != nil {
				t.Fatal(err)
			}
			bad := json.RawMessage(`{"kty":"EC","kid":"bad","crv":"P-999","x":"AAAA","y":"AAAA"}`)
			out, _ := json.Marshal(struct {
				Keys []json.RawMessage `json:"keys"`
			}{Keys: append([]json.RawMessage{bad}, parsed.Keys...)})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(out)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	validator, err := token.NewOIDCValidator(token.OIDCValidatorConfig{
		Issuer:      server.URL,
		Audience:    "clickhouse-auth",
		JWKSTTL:     time.Hour,
		HTTPTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v, want success despite one bad key", err)
	}

	raw := testutil.KubernetesJWT(t, key, testutil.TokenOptions{
		Issuer:            server.URL,
		Audience:          []string{"clickhouse-auth"},
		Namespace:         "analytics",
		ServiceAccount:    "ch-reader",
		ServiceAccountUID: "sa-uid-1",
		PodName:           "reader-0",
		PodUID:            "pod-uid-1",
	})
	if _, err := validator.Validate(context.Background(), raw); err != nil {
		t.Fatalf("Validate() error = %v, want success", err)
	}
}

// TestValidateServesStaleKeysWhenRefreshFails ensures a transient JWKS outage
// after a successful refresh does not take down authentication.
func TestValidateServesStaleKeysWhenRefreshFails(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	var fail atomic.Bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(testutil.JWKS(t, key))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	validator, err := token.NewOIDCValidator(token.OIDCValidatorConfig{
		Issuer:             server.URL,
		Audience:           "clickhouse-auth",
		JWKSTTL:            time.Millisecond,
		HTTPTimeout:        time.Second,
		MinRefreshInterval: time.Nanosecond, // always attempt the forced refresh
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Take the JWKS endpoint down and let the cached keys go stale.
	fail.Store(true)
	time.Sleep(5 * time.Millisecond)

	raw := testutil.KubernetesJWT(t, key, testutil.TokenOptions{
		Issuer:            server.URL,
		Audience:          []string{"clickhouse-auth"},
		Namespace:         "analytics",
		ServiceAccount:    "ch-reader",
		ServiceAccountUID: "sa-uid-1",
		PodName:           "reader-0",
		PodUID:            "pod-uid-1",
	})
	if _, err := validator.Validate(context.Background(), raw); err != nil {
		t.Fatalf("Validate() with stale keys error = %v, want success on cached keys", err)
	}
}
