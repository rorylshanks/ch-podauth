package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/rorylshanks/ch-podauth/internal/token"
)

func TestServiceAllowsMappedClickHouseUser(t *testing.T) {
	service := newTestService(t, token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	})

	decision := service.Authenticate(context.Background(), "reader", "jwt")
	if !decision.Allowed {
		t.Fatalf("Authenticate() allowed = false, reason = %s", decision.Reason)
	}
}

func TestServiceDeniesDisallowedClickHouseUser(t *testing.T) {
	service := newTestService(t, token.Identity{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	})

	decision := service.Authenticate(context.Background(), "admin", "jwt")
	if decision.Allowed || decision.Reason != "user_not_allowed" {
		t.Fatalf("Authenticate() = %+v, want user_not_allowed denial", decision)
	}
}

func TestServiceDeniesUnmappedServiceAccount(t *testing.T) {
	service := newTestService(t, token.Identity{
		Namespace:          "other",
		ServiceAccountName: "ch-reader",
		ServiceAccountUID:  "sa-uid",
		PodName:            "reader-0",
		PodUID:             "pod-uid",
	})

	decision := service.Authenticate(context.Background(), "reader", "jwt")
	if decision.Allowed || decision.Reason != "user_not_allowed" {
		t.Fatalf("Authenticate() = %+v, want user_not_allowed denial", decision)
	}
}

func TestServiceDeniesInvalidToken(t *testing.T) {
	service, err := NewService(fakeValidator{err: errors.New("bad token")}, []Mapping{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"reader"},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}

	decision := service.Authenticate(context.Background(), "reader", "jwt")
	if decision.Allowed || decision.Reason != "invalid_token" {
		t.Fatalf("Authenticate() = %+v, want invalid_token denial", decision)
	}
}

func newTestService(t *testing.T, id token.Identity) *Service {
	t.Helper()
	service, err := NewService(fakeValidator{id: id}, []Mapping{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"reader", "readonly"},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakeValidator struct {
	id  token.Identity
	err error
}

func (v fakeValidator) Validate(context.Context, string) (token.Identity, error) {
	return v.id, v.err
}
