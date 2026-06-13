package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken  = errors.New("invalid token")
	ErrUnknownKeyID  = errors.New("unknown key id")
	ErrInvalidClaims = errors.New("invalid claims")
)

type Identity struct {
	Subject            string
	Namespace          string
	ServiceAccountName string
	ServiceAccountUID  string
	PodName            string
	PodUID             string
}

type Validator interface {
	Validate(ctx context.Context, rawToken string) (Identity, error)
}

// RefreshObserver is notified of JWKS refresh outcomes so callers can export
// metrics without coupling this package to a metrics implementation.
type RefreshObserver interface {
	ObserveJWKSRefresh(success bool, keyCount int)
}

type OIDCValidatorConfig struct {
	Issuer             string
	Audience           string
	ClockSkew          time.Duration
	JWKSTTL            time.Duration
	HTTPTimeout        time.Duration
	HTTPClient         *http.Client
	MaxJWKSBytes       int64
	MinRefreshInterval time.Duration
	Observer           RefreshObserver
}

type OIDCValidator struct {
	cfg        OIDCValidatorConfig
	httpClient *http.Client

	mu        sync.RWMutex
	jwksURI   string
	keys      map[string]jwkKey
	refreshed time.Time

	// refreshMu single-flights network refreshes so concurrent unknown-kid
	// binds cannot stampede the JWKS endpoint. lastRefreshAttempt (guarded by
	// refreshMu) rate-limits forced refreshes.
	refreshMu          sync.Mutex
	lastRefreshAttempt time.Time
}

type jwkKey struct {
	KID       string
	Alg       string
	PublicKey any
}

func NewOIDCValidator(cfg OIDCValidatorConfig) (*OIDCValidator, error) {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if _, err := url.ParseRequestURI(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("issuer must be a valid URL: %w", err)
	}
	if cfg.Audience == "" {
		return nil, errors.New("audience is required")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.JWKSTTL == 0 {
		cfg.JWKSTTL = 10 * time.Minute
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if cfg.MaxJWKSBytes == 0 {
		cfg.MaxJWKSBytes = 1 << 20
	}
	if cfg.MinRefreshInterval == 0 {
		cfg.MinRefreshInterval = 15 * time.Second
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.HTTPTimeout}
	}

	return &OIDCValidator{
		cfg:        cfg,
		httpClient: client,
		keys:       make(map[string]jwkKey),
	}, nil
}

// Refresh fetches the JWKS unconditionally. It is single-flighted: concurrent
// callers are serialized so the JWKS endpoint is never hit more than once at a
// time.
func (v *OIDCValidator) Refresh(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	return v.doRefresh(ctx)
}

// forceRefresh refreshes the JWKS at most once per MinRefreshInterval. It backs
// the unknown-kid path so attacker-chosen key ids cannot stampede the JWKS
// endpoint, while still allowing genuine key rotation to be picked up promptly.
func (v *OIDCValidator) forceRefresh(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	if !v.lastRefreshAttempt.IsZero() && time.Since(v.lastRefreshAttempt) < v.cfg.MinRefreshInterval {
		return nil
	}
	return v.doRefresh(ctx)
}

// doRefresh performs the actual discovery + JWKS fetch and swaps in the new key
// set. Callers must hold refreshMu.
func (v *OIDCValidator) doRefresh(ctx context.Context) (err error) {
	v.lastRefreshAttempt = time.Now()

	if v.cfg.Observer != nil {
		defer func() {
			if err != nil {
				v.cfg.Observer.ObserveJWKSRefresh(false, 0)
			}
		}()
	}

	ctx, cancel := context.WithTimeout(ctx, v.cfg.HTTPTimeout)
	defer cancel()

	discoveryURL := v.cfg.Issuer + "/.well-known/openid-configuration"
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, discoveryURL, &discovery); err != nil {
		return fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	if strings.TrimRight(discovery.Issuer, "/") != v.cfg.Issuer {
		return fmt.Errorf("discovery issuer %q does not match configured issuer %q", discovery.Issuer, v.cfg.Issuer)
	}
	if discovery.JWKSURI == "" {
		return errors.New("discovery document missing jwks_uri")
	}
	if err := v.checkJWKSURI(discovery.JWKSURI); err != nil {
		return err
	}

	var raw rawJWKS
	if err := v.getJSON(ctx, discovery.JWKSURI, &raw); err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("JWKS did not contain any supported keys")
	}

	v.mu.Lock()
	v.jwksURI = discovery.JWKSURI
	v.keys = keys
	v.refreshed = time.Now()
	v.mu.Unlock()

	if v.cfg.Observer != nil {
		v.cfg.Observer.ObserveJWKSRefresh(true, len(keys))
	}
	return nil
}

// checkJWKSURI pins the jwks_uri to the configured issuer's scheme and host so a
// tampered discovery document cannot redirect the key fetch to an arbitrary host
// (SSRF / key substitution).
func (v *OIDCValidator) checkJWKSURI(jwksURI string) error {
	issuerURL, err := url.Parse(v.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("parse issuer URL: %w", err)
	}
	parsed, err := url.Parse(jwksURI)
	if err != nil {
		return fmt.Errorf("parse jwks_uri: %w", err)
	}
	if parsed.Scheme != issuerURL.Scheme || parsed.Host != issuerURL.Host {
		return fmt.Errorf("jwks_uri %q does not share the issuer scheme/host %q", jwksURI, v.cfg.Issuer)
	}
	return nil
}

func (v *OIDCValidator) Validate(ctx context.Context, rawToken string) (Identity, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("%w: expected compact JWT", ErrInvalidToken)
	}

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: decode header: %v", ErrInvalidToken, err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Identity{}, fmt.Errorf("%w: parse header: %v", ErrInvalidToken, err)
	}
	if header.KID == "" {
		return Identity{}, fmt.Errorf("%w: missing kid", ErrInvalidToken)
	}
	if !supportedAlg(header.Alg) {
		return Identity{}, fmt.Errorf("%w: unsupported alg %q", ErrInvalidToken, header.Alg)
	}

	key, err := v.keyFor(ctx, header.KID)
	if err != nil {
		return Identity{}, err
	}
	if key.Alg != "" && key.Alg != header.Alg {
		return Identity{}, fmt.Errorf("%w: key alg %q does not match token alg %q", ErrInvalidToken, key.Alg, header.Alg)
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: decode signature: %v", ErrInvalidToken, err)
	}
	if err := verifySignature(header.Alg, key.PublicKey, []byte(signingInput), signature); err != nil {
		return Identity{}, fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}

	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: decode payload: %v", ErrInvalidToken, err)
	}
	claims, err := decodeClaims(payloadBytes)
	if err != nil {
		return Identity{}, err
	}
	return v.validateClaims(claims, time.Now())
}

func (v *OIDCValidator) keyFor(ctx context.Context, kid string) (jwkKey, error) {
	if err := v.refreshIfStale(ctx); err != nil {
		return jwkKey{}, err
	}
	if key, ok := v.lookupKey(kid); ok {
		return key, nil
	}

	// Unknown kid: force a rate-limited refresh so genuine key rotation succeeds
	// without waiting for the TTL, while attacker-chosen kids cannot stampede the
	// JWKS endpoint.
	if err := v.forceRefresh(ctx); err != nil {
		return jwkKey{}, err
	}
	if key, ok := v.lookupKey(kid); ok {
		return key, nil
	}
	return jwkKey{}, fmt.Errorf("%w: %s", ErrUnknownKeyID, kid)
}

func (v *OIDCValidator) refreshIfStale(ctx context.Context) error {
	v.mu.RLock()
	refreshed := v.refreshed
	hasKeys := len(v.keys) > 0
	v.mu.RUnlock()
	if !refreshed.IsZero() && time.Since(refreshed) < v.cfg.JWKSTTL {
		return nil
	}
	if err := v.forceRefresh(ctx); err != nil {
		// Serve the last-known-good key set when a refresh fails so a transient
		// OIDC outage does not take down authentication.
		if hasKeys {
			return nil
		}
		return err
	}
	return nil
}

func (v *OIDCValidator) lookupKey(kid string) (jwkKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	return key, ok
}

func (v *OIDCValidator) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	limited := io.LimitReader(resp.Body, v.cfg.MaxJWKSBytes)
	dec := json.NewDecoder(limited)
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func (v *OIDCValidator) validateClaims(claims jwtClaims, now time.Time) (Identity, error) {
	if claims.Issuer != v.cfg.Issuer {
		return Identity{}, fmt.Errorf("%w: unexpected issuer", ErrInvalidClaims)
	}
	if !claims.Audience.Contains(v.cfg.Audience) {
		return Identity{}, fmt.Errorf("%w: missing required audience", ErrInvalidClaims)
	}
	if claims.ExpiresAt == 0 {
		return Identity{}, fmt.Errorf("%w: missing exp", ErrInvalidClaims)
	}
	nowUnix := now.Unix()
	skewSeconds := int64(v.cfg.ClockSkew.Seconds())
	if nowUnix > claims.ExpiresAt+skewSeconds {
		return Identity{}, fmt.Errorf("%w: token expired", ErrInvalidClaims)
	}
	if claims.NotBefore != 0 && nowUnix+skewSeconds < claims.NotBefore {
		return Identity{}, fmt.Errorf("%w: token not yet valid", ErrInvalidClaims)
	}
	if claims.IssuedAt != 0 && nowUnix+skewSeconds < claims.IssuedAt {
		return Identity{}, fmt.Errorf("%w: token issued in the future", ErrInvalidClaims)
	}

	id := claims.Identity()
	if id.Namespace == "" || id.ServiceAccountName == "" || id.ServiceAccountUID == "" || id.PodName == "" || id.PodUID == "" {
		return Identity{}, fmt.Errorf("%w: missing pod-bound service account claims", ErrInvalidClaims)
	}
	expectedSub := "system:serviceaccount:" + id.Namespace + ":" + id.ServiceAccountName
	if id.Subject != expectedSub {
		return Identity{}, fmt.Errorf("%w: subject does not match service account identity", ErrInvalidClaims)
	}
	return id, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}

type audience []string

func (a audience) Contains(expected string) bool {
	for _, got := range a {
		if got == expected {
			return true
		}
	}
	return false
}

func (a *audience) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = audience(many)
	return nil
}

type jwtClaims struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   audience `json:"aud"`
	ExpiresAt  int64    `json:"exp"`
	NotBefore  int64    `json:"nbf"`
	IssuedAt   int64    `json:"iat"`
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
		Pod struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
	} `json:"kubernetes.io"`
}

func (c jwtClaims) Identity() Identity {
	return Identity{
		Subject:            c.Subject,
		Namespace:          c.Kubernetes.Namespace,
		ServiceAccountName: c.Kubernetes.ServiceAccount.Name,
		ServiceAccountUID:  c.Kubernetes.ServiceAccount.UID,
		PodName:            c.Kubernetes.Pod.Name,
		PodUID:             c.Kubernetes.Pod.UID,
	}
}

func decodeClaims(data []byte) (jwtClaims, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var claims jwtClaims
	if err := dec.Decode(&claims); err != nil {
		return jwtClaims{}, fmt.Errorf("%w: parse claims: %v", ErrInvalidClaims, err)
	}
	return claims, nil
}

type rawJWKS struct {
	Keys []rawJWK `json:"keys"`
}

type rawJWK struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKS(raw rawJWKS) (map[string]jwkKey, error) {
	keys := make(map[string]jwkKey)
	for _, key := range raw.Keys {
		if key.KID == "" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		parsed, err := parseJWK(key)
		if err != nil {
			// Skip keys we cannot parse (e.g. an unsupported curve) so a single
			// bad key does not break validation for every other key.
			continue
		}
		if parsed.PublicKey != nil {
			keys[parsed.KID] = parsed
		}
	}
	return keys, nil
}

func parseJWK(raw rawJWK) (jwkKey, error) {
	switch raw.KTY {
	case "RSA":
		nBytes, err := decodeSegment(raw.N)
		if err != nil {
			return jwkKey{}, err
		}
		eBytes, err := decodeSegment(raw.E)
		if err != nil {
			return jwkKey{}, err
		}
		if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 4 {
			return jwkKey{}, errors.New("invalid RSA parameters")
		}
		var e int
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e < 3 {
			return jwkKey{}, errors.New("invalid RSA exponent")
		}
		return jwkKey{
			KID: raw.KID,
			Alg: raw.Alg,
			PublicKey: &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: e,
			},
		}, nil
	case "EC":
		curve := curveByName(raw.Crv)
		if curve == nil {
			return jwkKey{}, fmt.Errorf("unsupported EC curve %q", raw.Crv)
		}
		xBytes, err := decodeSegment(raw.X)
		if err != nil {
			return jwkKey{}, err
		}
		yBytes, err := decodeSegment(raw.Y)
		if err != nil {
			return jwkKey{}, err
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return jwkKey{}, errors.New("EC point is not on curve")
		}
		return jwkKey{
			KID: raw.KID,
			Alg: raw.Alg,
			PublicKey: &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
		}, nil
	default:
		return jwkKey{}, nil
	}
}

func supportedAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func verifySignature(alg string, key any, signingInput, signature []byte) error {
	h, hashID, err := hashForAlg(alg)
	if err != nil {
		return err
	}
	if _, err := h.Write(signingInput); err != nil {
		return err
	}
	digest := h.Sum(nil)

	switch alg {
	case "RS256", "RS384", "RS512":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA token signed by non-RSA key")
		}
		return rsa.VerifyPKCS1v15(pub, hashID, digest, signature)
	case "PS256", "PS384", "PS512":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA-PSS token signed by non-RSA key")
		}
		return rsa.VerifyPSS(pub, hashID, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256", "ES384", "ES512":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ECDSA token signed by non-ECDSA key")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return errors.New("invalid ECDSA signature size")
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	default:
		return errors.New("unsupported algorithm")
	}
}

func hashForAlg(alg string) (hash.Hash, crypto.Hash, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return sha256.New(), crypto.SHA256, nil
	case "RS384", "PS384", "ES384":
		return sha512.New384(), crypto.SHA384, nil
	case "RS512", "PS512", "ES512":
		return sha512.New(), crypto.SHA512, nil
	default:
		return nil, 0, errors.New("unsupported algorithm")
	}
}

func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func Fingerprint(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return fmt.Sprintf("%x", sum[:8])
}
