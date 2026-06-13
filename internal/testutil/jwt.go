package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

type RSAKey struct {
	KID     string
	Private *rsa.PrivateKey
}

type TokenOptions struct {
	Issuer            string
	Audience          any
	Subject           string
	Namespace         string
	ServiceAccount    string
	ServiceAccountUID string
	PodName           string
	PodUID            string
	IssuedAt          time.Time
	NotBefore         time.Time
	ExpiresAt         time.Time
	KID               string
}

func NewRSAKey(t testing.TB, kid string) RSAKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return RSAKey{KID: kid, Private: key}
}

func JWKS(t testing.TB, keys ...RSAKey) []byte {
	t.Helper()
	type jwk struct {
		KTY string `json:"kty"`
		Use string `json:"use"`
		KID string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	body := struct {
		Keys []jwk `json:"keys"`
	}{}
	for _, key := range keys {
		pub := key.Private.PublicKey
		body.Keys = append(body.Keys, jwk{
			KTY: "RSA",
			Use: "sig",
			KID: key.KID,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func KubernetesJWT(t testing.TB, key RSAKey, opts TokenOptions) string {
	t.Helper()
	if opts.KID == "" {
		opts.KID = key.KID
	}
	if opts.IssuedAt.IsZero() {
		opts.IssuedAt = time.Now().Add(-time.Minute)
	}
	if opts.NotBefore.IsZero() {
		opts.NotBefore = opts.IssuedAt
	}
	if opts.ExpiresAt.IsZero() {
		opts.ExpiresAt = time.Now().Add(time.Hour)
	}
	if opts.Subject == "" {
		opts.Subject = "system:serviceaccount:" + opts.Namespace + ":" + opts.ServiceAccount
	}
	if opts.Audience == nil {
		opts.Audience = []string{"clickhouse-auth"}
	}

	header := map[string]any{
		"alg": "RS256",
		"kid": opts.KID,
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss": opts.Issuer,
		"sub": opts.Subject,
		"aud": opts.Audience,
		"iat": opts.IssuedAt.Unix(),
		"nbf": opts.NotBefore.Unix(),
		"exp": opts.ExpiresAt.Unix(),
		"kubernetes.io": map[string]any{
			"namespace": opts.Namespace,
			"serviceaccount": map[string]any{
				"name": opts.ServiceAccount,
				"uid":  opts.ServiceAccountUID,
			},
			"pod": map[string]any{
				"name": opts.PodName,
				"uid":  opts.PodUID,
			},
		},
	}
	return SignJWT(t, key, header, claims)
}

func SignJWT(t testing.TB, key RSAKey, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.Private, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
