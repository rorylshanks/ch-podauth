package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus collectors for the bridge and serves them from a
// private registry (so it never collides with the global default registry and
// tests can construct independent instances).
type Metrics struct {
	registry *prometheus.Registry

	bindsTotal          prometheus.Counter
	bindsSuccess        prometheus.Counter
	bindsFailure        prometheus.Counter
	requestTooLarge     prometheus.Counter
	protocolErrors      prometheus.Counter
	connectionsRejected prometheus.Counter
	bindFailureReasons  *prometheus.CounterVec
	bindDuration        prometheus.Histogram

	jwksRefreshes   *prometheus.CounterVec
	jwksLastSuccess prometheus.Gauge
	jwksKeys        prometheus.Gauge

	activeConnections prometheus.Gauge
	maxConnections    prometheus.Gauge
}

func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		bindsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_binds_total",
			Help: "Total LDAP simple-bind attempts processed.",
		}),
		bindsSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_bind_success_total",
			Help: "LDAP binds that were authenticated and authorized.",
		}),
		bindsFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_bind_failure_total",
			Help: "LDAP binds that were denied.",
		}),
		requestTooLarge: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_request_too_large_total",
			Help: "LDAP requests or credentials rejected for exceeding size limits.",
		}),
		protocolErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_protocol_errors_total",
			Help: "LDAP requests rejected because they could not be parsed.",
		}),
		connectionsRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_connections_rejected_total",
			Help: "Connections rejected because the concurrent-connection limit was reached.",
		}),
		bindFailureReasons: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ch_podauth_ldap_bind_failures_by_reason_total",
			Help: "LDAP bind denials grouped by reason.",
		}, []string{"reason"}),
		bindDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ch_podauth_bind_duration_seconds",
			Help:    "Duration of LDAP bind authentication (token validation + authorization).",
			Buckets: prometheus.DefBuckets,
		}),
		jwksRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ch_podauth_jwks_refresh_total",
			Help: "JWKS refreshes grouped by result.",
		}, []string{"result"}),
		jwksLastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ch_podauth_jwks_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful JWKS refresh.",
		}),
		jwksKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ch_podauth_jwks_keys",
			Help: "Number of usable keys currently cached from the JWKS.",
		}),
		activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ch_podauth_active_connections",
			Help: "LDAP connections currently being served.",
		}),
		maxConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ch_podauth_max_connections",
			Help: "Configured maximum number of concurrent LDAP connections.",
		}),
	}

	m.registry.MustRegister(
		m.bindsTotal,
		m.bindsSuccess,
		m.bindsFailure,
		m.requestTooLarge,
		m.protocolErrors,
		m.connectionsRejected,
		m.bindFailureReasons,
		m.bindDuration,
		m.jwksRefreshes,
		m.jwksLastSuccess,
		m.jwksKeys,
		m.activeConnections,
		m.maxConnections,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *Metrics) ObserveBind(success bool, reason string) {
	m.bindsTotal.Inc()
	if success {
		m.bindsSuccess.Inc()
		return
	}
	m.bindsFailure.Inc()
	if reason == "" {
		reason = "unknown"
	}
	m.bindFailureReasons.WithLabelValues(reason).Inc()
}

func (m *Metrics) ObserveBindDuration(seconds float64) {
	m.bindDuration.Observe(seconds)
}

func (m *Metrics) ObserveRequestTooLarge() {
	m.requestTooLarge.Inc()
}

func (m *Metrics) ObserveProtocolError() {
	m.protocolErrors.Inc()
}

func (m *Metrics) ObserveConnectionRejected() {
	m.connectionsRejected.Inc()
}

// ObserveJWKSRefresh records the outcome of a JWKS refresh. On success it also
// records the time and the number of usable keys now cached.
func (m *Metrics) ObserveJWKSRefresh(success bool, keyCount int) {
	if success {
		m.jwksRefreshes.WithLabelValues("success").Inc()
		m.jwksLastSuccess.SetToCurrentTime()
		m.jwksKeys.Set(float64(keyCount))
		return
	}
	m.jwksRefreshes.WithLabelValues("failure").Inc()
}

func (m *Metrics) IncActiveConnections() {
	m.activeConnections.Inc()
}

func (m *Metrics) DecActiveConnections() {
	m.activeConnections.Dec()
}

func (m *Metrics) SetMaxConnections(n int) {
	m.maxConnections.Set(float64(n))
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
