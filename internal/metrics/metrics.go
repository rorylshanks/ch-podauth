package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type Metrics struct {
	bindsTotal         atomic.Uint64
	bindsSuccess       atomic.Uint64
	bindsFailure       atomic.Uint64
	requestTooLarge    atomic.Uint64
	protocolErrors     atomic.Uint64
	reasonMu           sync.RWMutex
	bindFailureReasons map[string]uint64
}

func New() *Metrics {
	return &Metrics{
		bindFailureReasons: make(map[string]uint64),
	}
}

func (m *Metrics) ObserveBind(success bool, reason string) {
	m.bindsTotal.Add(1)
	if success {
		m.bindsSuccess.Add(1)
		return
	}
	m.bindsFailure.Add(1)
	if reason == "" {
		reason = "unknown"
	}
	m.reasonMu.Lock()
	m.bindFailureReasons[reason]++
	m.reasonMu.Unlock()
}

func (m *Metrics) ObserveRequestTooLarge() {
	m.requestTooLarge.Add(1)
}

func (m *Metrics) ObserveProtocolError() {
	m.protocolErrors.Add(1)
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# TYPE ch_podauth_ldap_binds_total counter\n")
		fmt.Fprintf(w, "ch_podauth_ldap_binds_total %d\n", m.bindsTotal.Load())
		fmt.Fprintf(w, "# TYPE ch_podauth_ldap_bind_success_total counter\n")
		fmt.Fprintf(w, "ch_podauth_ldap_bind_success_total %d\n", m.bindsSuccess.Load())
		fmt.Fprintf(w, "# TYPE ch_podauth_ldap_bind_failure_total counter\n")
		fmt.Fprintf(w, "ch_podauth_ldap_bind_failure_total %d\n", m.bindsFailure.Load())
		fmt.Fprintf(w, "# TYPE ch_podauth_ldap_request_too_large_total counter\n")
		fmt.Fprintf(w, "ch_podauth_ldap_request_too_large_total %d\n", m.requestTooLarge.Load())
		fmt.Fprintf(w, "# TYPE ch_podauth_ldap_protocol_errors_total counter\n")
		fmt.Fprintf(w, "ch_podauth_ldap_protocol_errors_total %d\n", m.protocolErrors.Load())

		reasons := m.failureReasons()
		if len(reasons) > 0 {
			fmt.Fprintf(w, "# TYPE ch_podauth_ldap_bind_failures_by_reason_total counter\n")
			for _, reason := range reasons {
				fmt.Fprintf(w, "ch_podauth_ldap_bind_failures_by_reason_total{reason=%q} %d\n", reason.Name, reason.Value)
			}
		}
	})
}

type reasonCount struct {
	Name  string
	Value uint64
}

func (m *Metrics) failureReasons() []reasonCount {
	m.reasonMu.RLock()
	defer m.reasonMu.RUnlock()
	result := make([]reasonCount, 0, len(m.bindFailureReasons))
	for reason, value := range m.bindFailureReasons {
		result = append(result, reasonCount{Name: sanitizeLabel(reason), Value: value})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
