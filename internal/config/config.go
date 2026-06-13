package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rorylshanks/ch-podauth/internal/auth"
	"gopkg.in/yaml.v3"
)

type Config struct {
	LDAP     LDAPConfig      `yaml:"ldap" json:"ldap"`
	HTTP     HTTPConfig      `yaml:"http" json:"http"`
	OIDC     OIDCConfig      `yaml:"oidc" json:"oidc"`
	Logging  LoggingConfig   `yaml:"logging" json:"logging"`
	Mappings []MappingConfig `yaml:"mappings" json:"mappings"`
}

type LDAPConfig struct {
	ListenAddr         string   `yaml:"listen_addr" json:"listen_addr"`
	MaxRequestBytes    int      `yaml:"max_request_bytes" json:"max_request_bytes"`
	MaxCredentialBytes int      `yaml:"max_credential_bytes" json:"max_credential_bytes"`
	MaxConnections     int      `yaml:"max_connections" json:"max_connections"`
	ReadTimeout        Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout       Duration `yaml:"write_timeout" json:"write_timeout"`
}

type HTTPConfig struct {
	ListenAddr string   `yaml:"listen_addr" json:"listen_addr"`
	Timeout    Duration `yaml:"timeout" json:"timeout"`
}

type OIDCConfig struct {
	Issuer             string   `yaml:"issuer" json:"issuer"`
	Audience           string   `yaml:"audience" json:"audience"`
	ClockSkew          Duration `yaml:"clock_skew" json:"clock_skew"`
	JWKSTTL            Duration `yaml:"jwks_ttl" json:"jwks_ttl"`
	HTTPTimeout        Duration `yaml:"http_timeout" json:"http_timeout"`
	MaxJWKSBytes       int64    `yaml:"max_jwks_bytes" json:"max_jwks_bytes"`
	MinRefreshInterval Duration `yaml:"min_refresh_interval" json:"min_refresh_interval"`
}

type LoggingConfig struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
}

type MappingConfig struct {
	Namespace          string   `yaml:"namespace" json:"namespace"`
	ServiceAccountName string   `yaml:"service_account" json:"service_account"`
	ClickHouseUsers    []string `yaml:"clickhouse_users" json:"clickhouse_users"`
}

type Duration struct {
	time.Duration
}

func Default() Config {
	return Config{
		LDAP: LDAPConfig{
			ListenAddr:         "127.0.0.1:1389",
			MaxRequestBytes:    128 * 1024,
			MaxCredentialBytes: 32 * 1024,
			MaxConnections:     256,
			ReadTimeout:        Duration{5 * time.Second},
			WriteTimeout:       Duration{5 * time.Second},
		},
		HTTP: HTTPConfig{
			ListenAddr: "127.0.0.1:8080",
			Timeout:    Duration{5 * time.Second},
		},
		OIDC: OIDCConfig{
			Audience:           "clickhouse-auth",
			ClockSkew:          Duration{30 * time.Second},
			JWKSTTL:            Duration{10 * time.Minute},
			HTTPTimeout:        Duration{5 * time.Second},
			MaxJWKSBytes:       1 << 20,
			MinRefreshInterval: Duration{15 * time.Second},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = os.Getenv("CH_PODAUTH_CONFIG")
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, err
		}
	}
	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if err := validateAddr(c.LDAP.ListenAddr, "ldap.listen_addr"); err != nil {
		return err
	}
	if c.HTTP.ListenAddr != "" {
		if err := validateAddr(c.HTTP.ListenAddr, "http.listen_addr"); err != nil {
			return err
		}
	}
	if c.OIDC.Issuer == "" {
		return errors.New("oidc.issuer is required")
	}
	if c.OIDC.Audience == "" {
		return errors.New("oidc.audience is required")
	}
	if c.LDAP.MaxRequestBytes <= 0 {
		return errors.New("ldap.max_request_bytes must be positive")
	}
	if c.LDAP.MaxCredentialBytes <= 0 {
		return errors.New("ldap.max_credential_bytes must be positive")
	}
	if c.LDAP.MaxCredentialBytes > c.LDAP.MaxRequestBytes {
		return errors.New("ldap.max_credential_bytes cannot exceed ldap.max_request_bytes")
	}
	if c.LDAP.MaxConnections <= 0 {
		return errors.New("ldap.max_connections must be positive")
	}
	if c.OIDC.ClockSkew.Duration < 0 || c.OIDC.JWKSTTL.Duration <= 0 || c.OIDC.HTTPTimeout.Duration <= 0 {
		return errors.New("oidc durations must be positive, except clock_skew may be zero")
	}
	if c.OIDC.MinRefreshInterval.Duration < 0 {
		return errors.New("oidc.min_refresh_interval cannot be negative")
	}
	if c.OIDC.MaxJWKSBytes <= 0 {
		return errors.New("oidc.max_jwks_bytes must be positive")
	}
	if len(c.Mappings) == 0 {
		return errors.New("at least one mapping is required")
	}
	for i, mapping := range c.Mappings {
		if mapping.Namespace == "" || mapping.ServiceAccountName == "" || len(mapping.ClickHouseUsers) == 0 {
			return fmt.Errorf("mapping %d requires namespace, service_account, and clickhouse_users", i)
		}
	}
	return nil
}

func (c Config) AuthMappings() []auth.Mapping {
	result := make([]auth.Mapping, 0, len(c.Mappings))
	for _, mapping := range c.Mappings {
		result = append(result, auth.Mapping{
			Namespace:          mapping.Namespace,
			ServiceAccountName: mapping.ServiceAccountName,
			ClickHouseUsers:    mapping.ClickHouseUsers,
		})
	}
	return result
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		if value.Tag == "!!int" {
			seconds, err := strconv.ParseInt(value.Value, 10, 64)
			if err != nil {
				return err
			}
			d.Duration = time.Duration(seconds) * time.Second
			return nil
		}
		parsed, err := time.ParseDuration(value.Value)
		if err != nil {
			return err
		}
		d.Duration = parsed
		return nil
	}
	return errors.New("duration must be a scalar")
}

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		d.Duration = parsed
		return nil
	}
	var seconds int64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return err
	}
	d.Duration = time.Duration(seconds) * time.Second
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func applyEnv(cfg *Config) error {
	overrideString(&cfg.LDAP.ListenAddr, "CH_PODAUTH_LDAP_ADDR")
	if err := overrideInt(&cfg.LDAP.MaxRequestBytes, "CH_PODAUTH_LDAP_MAX_REQUEST_BYTES"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.LDAP.MaxCredentialBytes, "CH_PODAUTH_LDAP_MAX_CREDENTIAL_BYTES"); err != nil {
		return err
	}
	if err := overrideInt(&cfg.LDAP.MaxConnections, "CH_PODAUTH_LDAP_MAX_CONNECTIONS"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.LDAP.ReadTimeout, "CH_PODAUTH_LDAP_READ_TIMEOUT"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.LDAP.WriteTimeout, "CH_PODAUTH_LDAP_WRITE_TIMEOUT"); err != nil {
		return err
	}

	overrideString(&cfg.HTTP.ListenAddr, "CH_PODAUTH_HTTP_ADDR")
	if err := overrideDuration(&cfg.HTTP.Timeout, "CH_PODAUTH_HTTP_TIMEOUT"); err != nil {
		return err
	}

	overrideString(&cfg.OIDC.Issuer, "CH_PODAUTH_OIDC_ISSUER")
	overrideString(&cfg.OIDC.Audience, "CH_PODAUTH_AUDIENCE")
	if err := overrideDuration(&cfg.OIDC.ClockSkew, "CH_PODAUTH_CLOCK_SKEW"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.OIDC.JWKSTTL, "CH_PODAUTH_JWKS_TTL"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.OIDC.HTTPTimeout, "CH_PODAUTH_OIDC_HTTP_TIMEOUT"); err != nil {
		return err
	}
	if err := overrideInt64(&cfg.OIDC.MaxJWKSBytes, "CH_PODAUTH_MAX_JWKS_BYTES"); err != nil {
		return err
	}
	if err := overrideDuration(&cfg.OIDC.MinRefreshInterval, "CH_PODAUTH_MIN_REFRESH_INTERVAL"); err != nil {
		return err
	}

	overrideString(&cfg.Logging.Level, "CH_PODAUTH_LOG_LEVEL")
	overrideString(&cfg.Logging.Format, "CH_PODAUTH_LOG_FORMAT")

	if raw := os.Getenv("CH_PODAUTH_MAPPINGS"); raw != "" {
		var mappings []MappingConfig
		if err := json.Unmarshal([]byte(raw), &mappings); err != nil {
			return fmt.Errorf("CH_PODAUTH_MAPPINGS: %w", err)
		}
		cfg.Mappings = mappings
	}
	return nil
}

func overrideString(dst *string, name string) {
	if value := os.Getenv(name); value != "" {
		*dst = value
	}
}

func overrideInt(dst *int, name string) error {
	if value := os.Getenv(name); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		*dst = parsed
	}
	return nil
}

func overrideInt64(dst *int64, name string) error {
	if value := os.Getenv(name); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		*dst = parsed
	}
	return nil
}

func overrideDuration(dst *Duration, name string) error {
	if value := os.Getenv(name); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		dst.Duration = parsed
	}
	return nil
}

func validateAddr(addr, field string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("%s is required", field)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s must be host:port: %w", field, err)
	}
	if host == "" {
		return fmt.Errorf("%s must include an explicit host", field)
	}
	if port == "" {
		return fmt.Errorf("%s must include a port", field)
	}
	return nil
}
