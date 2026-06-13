package token_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rorylshanks/ch-podauth/internal/testutil"
	"github.com/rorylshanks/ch-podauth/internal/token"
)

func TestOIDCValidatorValidatesProjectedServiceAccountToken(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	issuer, validator := newOIDCTestValidator(t, key)

	raw := validToken(t, key, issuer, nil)
	id, err := validator.Validate(context.Background(), raw)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if id.Namespace != "analytics" || id.ServiceAccountName != "ch-reader" || id.PodName != "reader-0" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestOIDCValidatorRejectsExpiredToken(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	issuer, validator := newOIDCTestValidator(t, key)
	raw := validToken(t, key, issuer, func(opts *testutil.TokenOptions) {
		opts.ExpiresAt = time.Now().Add(-time.Hour)
	})

	_, err := validator.Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Validate() error = %v, want expired", err)
	}
}

func TestOIDCValidatorRejectsWrongAudience(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	issuer, validator := newOIDCTestValidator(t, key)
	raw := validToken(t, key, issuer, func(opts *testutil.TokenOptions) {
		opts.Audience = []string{"other-audience"}
	})

	_, err := validator.Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("Validate() error = %v, want audience rejection", err)
	}
}

func TestOIDCValidatorRejectsWrongIssuer(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	issuer, validator := newOIDCTestValidator(t, key)
	raw := validToken(t, key, issuer, func(opts *testutil.TokenOptions) {
		opts.Issuer = issuer + "/unexpected"
	})

	_, err := validator.Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("Validate() error = %v, want issuer rejection", err)
	}
}

func TestOIDCValidatorRejectsUnknownKeyID(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	otherKey := testutil.NewRSAKey(t, "key-2")
	issuer, validator := newOIDCTestValidator(t, key)
	raw := validToken(t, otherKey, issuer, nil)

	_, err := validator.Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "unknown key id") {
		t.Fatalf("Validate() error = %v, want unknown key id", err)
	}
}

func TestOIDCValidatorRejectsTokensWithoutPodBinding(t *testing.T) {
	key := testutil.NewRSAKey(t, "key-1")
	issuer, validator := newOIDCTestValidator(t, key)
	raw := validToken(t, key, issuer, func(opts *testutil.TokenOptions) {
		opts.PodName = ""
		opts.PodUID = ""
	})

	_, err := validator.Validate(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "pod-bound") {
		t.Fatalf("Validate() error = %v, want pod-bound rejection", err)
	}
}

func newOIDCTestValidator(t *testing.T, key testutil.RSAKey) (string, *token.OIDCValidator) {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		Issuer:      server.URL,
		Audience:    "clickhouse-auth",
		ClockSkew:   0,
		JWKSTTL:     time.Hour,
		HTTPTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return server.URL, validator
}

func validToken(t *testing.T, key testutil.RSAKey, issuer string, mutate func(*testutil.TokenOptions)) string {
	t.Helper()
	opts := testutil.TokenOptions{
		Issuer:            issuer,
		Audience:          []string{"clickhouse-auth"},
		Namespace:         "analytics",
		ServiceAccount:    "ch-reader",
		ServiceAccountUID: "sa-uid-1",
		PodName:           "reader-0",
		PodUID:            "pod-uid-1",
		IssuedAt:          time.Now().Add(-time.Minute),
		NotBefore:         time.Now().Add(-time.Minute),
		ExpiresAt:         time.Now().Add(time.Hour),
	}
	if mutate != nil {
		mutate(&opts)
	}
	return testutil.KubernetesJWT(t, key, opts)
}
