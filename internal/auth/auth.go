package auth

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"

	"github.com/rorylshanks/ch-podauth/internal/metrics"
	"github.com/rorylshanks/ch-podauth/internal/token"
)

var ErrDenied = errors.New("denied")

type Mapping struct {
	Namespace          string
	ServiceAccountName string
	ClickHouseUsers    []string
}

type Decision struct {
	Allowed     bool
	Reason      string
	Fingerprint string
	Identity    token.Identity
}

type Service struct {
	validator token.Validator
	mappings  map[string]map[string]struct{}
	logger    *slog.Logger
	metrics   *metrics.Metrics
}

func NewService(validator token.Validator, mappings []Mapping, logger *slog.Logger, metrics *metrics.Metrics) (*Service, error) {
	if validator == nil {
		return nil, errors.New("validator is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	compiled := make(map[string]map[string]struct{})
	for _, mapping := range mappings {
		if mapping.Namespace == "" || mapping.ServiceAccountName == "" || len(mapping.ClickHouseUsers) == 0 {
			return nil, errors.New("mappings require namespace, service account, and at least one ClickHouse user")
		}
		key := identityKey(mapping.Namespace, mapping.ServiceAccountName)
		if _, ok := compiled[key]; !ok {
			compiled[key] = make(map[string]struct{})
		}
		for _, user := range mapping.ClickHouseUsers {
			user = strings.TrimSpace(user)
			if user == "" {
				continue
			}
			compiled[key][user] = struct{}{}
		}
		if len(compiled[key]) == 0 {
			return nil, errors.New("mapping contains no non-empty ClickHouse users")
		}
	}
	if len(compiled) == 0 {
		return nil, errors.New("at least one mapping is required")
	}
	return &Service{
		validator: validator,
		mappings:  compiled,
		logger:    logger,
		metrics:   metrics,
	}, nil
}

func (s *Service) Authenticate(ctx context.Context, clickhouseUser, password string) Decision {
	fingerprint := token.Fingerprint(password)
	if clickhouseUser == "" {
		s.observe(false, "empty_username")
		s.logger.Warn("ldap bind denied",
			"reason", "empty_username",
			"token_fingerprint", fingerprint,
		)
		return Decision{Allowed: false, Reason: "empty_username", Fingerprint: fingerprint}
	}

	id, err := s.validator.Validate(ctx, password)
	if err != nil {
		s.observe(false, "invalid_token")
		s.logger.Warn("ldap bind denied",
			"reason", "invalid_token",
			"clickhouse_user", clickhouseUser,
			"token_fingerprint", fingerprint,
		)
		return Decision{Allowed: false, Reason: "invalid_token", Fingerprint: fingerprint}
	}

	if !s.Allowed(id, clickhouseUser) {
		s.observe(false, "user_not_allowed")
		s.logger.Warn("ldap bind denied",
			"reason", "user_not_allowed",
			"namespace", id.Namespace,
			"service_account", id.ServiceAccountName,
			"pod", id.PodName,
			"clickhouse_user", clickhouseUser,
			"token_fingerprint", fingerprint,
		)
		return Decision{Allowed: false, Reason: "user_not_allowed", Fingerprint: fingerprint, Identity: id}
	}

	s.observe(true, "success")
	s.logger.Info("ldap bind allowed",
		"namespace", id.Namespace,
		"service_account", id.ServiceAccountName,
		"pod", id.PodName,
		"clickhouse_user", clickhouseUser,
		"token_fingerprint", fingerprint,
	)
	return Decision{Allowed: true, Reason: "success", Fingerprint: fingerprint, Identity: id}
}

func (s *Service) Allowed(id token.Identity, clickhouseUser string) bool {
	users, ok := s.mappings[identityKey(id.Namespace, id.ServiceAccountName)]
	if !ok {
		return false
	}
	_, ok = users[clickhouseUser]
	return ok
}

func (s *Service) Mappings() []Mapping {
	result := make([]Mapping, 0, len(s.mappings))
	for key, users := range s.mappings {
		parts := strings.SplitN(key, "/", 2)
		chUsers := make([]string, 0, len(users))
		for user := range users {
			chUsers = append(chUsers, user)
		}
		sort.Strings(chUsers)
		result = append(result, Mapping{
			Namespace:          parts[0],
			ServiceAccountName: parts[1],
			ClickHouseUsers:    chUsers,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return identityKey(result[i].Namespace, result[i].ServiceAccountName) < identityKey(result[j].Namespace, result[j].ServiceAccountName)
	})
	return result
}

func (s *Service) observe(success bool, reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.ObserveBind(success, reason)
}

func identityKey(namespace, serviceAccount string) string {
	return namespace + "/" + serviceAccount
}
