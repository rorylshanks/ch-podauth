package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExposesMetrics(t *testing.T) {
	m := New()
	m.ObserveBind(true, "success")
	m.ObserveBind(false, "user_not_allowed")
	m.ObserveBindDuration(0.123)
	m.ObserveConnectionRejected()
	m.ObserveProtocolError()
	m.ObserveRequestTooLarge()
	m.ObserveJWKSRefresh(true, 3)
	m.ObserveJWKSRefresh(false, 0)
	m.IncActiveConnections()
	m.SetMaxConnections(256)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	want := []string{
		"ch_podauth_ldap_binds_total 2",
		"ch_podauth_ldap_bind_success_total 1",
		"ch_podauth_ldap_bind_failure_total 1",
		`ch_podauth_ldap_bind_failures_by_reason_total{reason="user_not_allowed"} 1`,
		"ch_podauth_ldap_request_too_large_total 1",
		"ch_podauth_ldap_protocol_errors_total 1",
		"ch_podauth_ldap_connections_rejected_total 1",
		"ch_podauth_bind_duration_seconds_count 1",
		`ch_podauth_jwks_refresh_total{result="success"} 1`,
		`ch_podauth_jwks_refresh_total{result="failure"} 1`,
		"ch_podauth_jwks_keys 3",
		"ch_podauth_active_connections 1",
		"ch_podauth_max_connections 256",
		// Go runtime / process collectors registered by New().
		"go_goroutines",
		"process_start_time_seconds",
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("metrics output missing %q\n---\n%s", w, body)
		}
	}
}
