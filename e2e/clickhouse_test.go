//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rorylshanks/ch-podauth/internal/auth"
	"github.com/rorylshanks/ch-podauth/internal/ldapserver"
	"github.com/rorylshanks/ch-podauth/internal/metrics"
	"github.com/rorylshanks/ch-podauth/internal/testutil"
	"github.com/rorylshanks/ch-podauth/internal/token"
)

const clickHouseImage = "clickhouse/clickhouse-server:25.3"

func TestClickHouseLDAPBridge(t *testing.T) {
	requireDocker(t)

	key := testutil.NewRSAKey(t, "key-1")
	issuer, validator := newOIDCTestValidator(t, key)
	metricSet := metrics.New()
	var bridgeLogs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&bridgeLogs, nil))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("bridge logs:\n%s", bridgeLogs.String())
		}
	})
	authService, err := auth.NewService(validator, []auth.Mapping{{
		Namespace:          "analytics",
		ServiceAccountName: "ch-reader",
		ClickHouseUsers:    []string{"reader"},
	}}, logger, metricSet)
	if err != nil {
		t.Fatal(err)
	}

	ldapPort := freePort(t)
	ldapSrv, err := ldapserver.New(ldapserver.Config{
		ListenAddr:         fmt.Sprintf("0.0.0.0:%d", ldapPort),
		MaxRequestBytes:    128 * 1024,
		MaxCredentialBytes: 32 * 1024,
		ReadTimeout:        5 * time.Second,
		WriteTimeout:       5 * time.Second,
	}, authService, logger, metricSet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- ldapSrv.ListenAndServe(ctx) }()
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", ldapPort))

	nativePort := freePort(t)
	httpPort := freePort(t)
	interserverPort := freePort(t)
	container := "ch-podauth-e2e-" + strings.ToLower(randomSuffix(t))
	t.Cleanup(func() {
		_ = runDocker(context.Background(), "rm", "-f", container)
	})

	configDir := writeClickHouseConfig(t, ldapPort, nativePort, httpPort, interserverPort)
	args := []string{
		"run", "-d", "--name", container,
		"--network", "host",
		"-e", "CLICKHOUSE_SKIP_USER_SETUP=1",
		"-v", filepath.Join(configDir, "config.d") + ":/etc/clickhouse-server/config.d:ro",
		"-v", filepath.Join(configDir, "users.d") + ":/etc/clickhouse-server/users.d:ro",
		clickHouseImage,
	}
	if out, err := dockerOutput(context.Background(), args...); err != nil {
		t.Fatalf("docker run failed: %v\n%s", err, out)
	}
	waitForClickHouse(t, container, nativePort)
	if out, err := dockerOutput(context.Background(), "exec", container, "clickhouse-client", "--port", fmt.Sprint(nativePort), "--query", "SELECT name, auth_type FROM system.users WHERE name IN ('reader', 'writer') ORDER BY name"); err == nil {
		t.Logf("clickhouse users:\n%s", out)
	} else {
		t.Logf("could not query system.users: %v\n%s", err, out)
	}

	rawToken := testutil.KubernetesJWT(t, key, testutil.TokenOptions{
		Issuer:            issuer,
		Audience:          []string{"clickhouse-auth"},
		Namespace:         "analytics",
		ServiceAccount:    "ch-reader",
		ServiceAccountUID: "sa-uid-1",
		PodName:           "reader-0",
		PodUID:            "pod-uid-1",
	})
	out, err := dockerOutput(context.Background(),
		"exec", container,
		"clickhouse-client",
		"--host", "127.0.0.1",
		"--port", fmt.Sprint(nativePort),
		"--user", "reader",
		"--password", rawToken,
		"--query", "SELECT currentUser()",
	)
	if err != nil {
		dumpClickHouseDiagnostics(t, container)
		t.Fatalf("clickhouse authenticated query failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(out) != "reader" {
		t.Fatalf("currentUser() = %q, want reader", strings.TrimSpace(out))
	}

	deniedOut, err := dockerOutput(context.Background(),
		"exec", container,
		"clickhouse-client",
		"--host", "127.0.0.1",
		"--port", fmt.Sprint(nativePort),
		"--user", "writer",
		"--password", rawToken,
		"--query", "SELECT 1",
	)
	if err == nil {
		t.Fatalf("disallowed user query succeeded unexpectedly: %s", deniedOut)
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

func writeClickHouseConfig(t *testing.T, ldapPort, nativePort, httpPort, interserverPort int) string {
	t.Helper()
	dir := t.TempDir()
	configD := filepath.Join(dir, "config.d")
	usersD := filepath.Join(dir, "users.d")
	if err := os.MkdirAll(configD, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(usersD, 0o755); err != nil {
		t.Fatal(err)
	}
	configXML := fmt.Sprintf(`<clickhouse>
  <tcp_port>%d</tcp_port>
  <http_port>%d</http_port>
  <interserver_http_port>%d</interserver_http_port>
  <ldap_servers>
    <podauth>
      <host>127.0.0.1</host>
      <port>%d</port>
      <enable_tls>no</enable_tls>
      <bind_dn>{user_name}</bind_dn>
      <verification_cooldown>0</verification_cooldown>
    </podauth>
  </ldap_servers>
</clickhouse>
`, nativePort, httpPort, interserverPort, ldapPort)
	usersXML := `<clickhouse>
  <users>
    <reader>
      <ldap>
        <server>podauth</server>
      </ldap>
      <profile>default</profile>
      <quota>default</quota>
    </reader>
    <writer>
      <ldap>
        <server>podauth</server>
      </ldap>
      <profile>default</profile>
      <quota>default</quota>
    </writer>
  </users>
</clickhouse>
`
	if err := os.WriteFile(filepath.Join(configD, "podauth.xml"), []byte(configXML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(usersD, "podauth-users.xml"), []byte(usersXML), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not available")
	}
	if out, err := dockerOutput(context.Background(), "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon not available: %v\n%s", err, out)
	}
}

func waitForClickHouse(t *testing.T, container string, nativePort int) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := dockerOutput(context.Background(), "exec", container, "clickhouse-client", "--port", fmt.Sprint(nativePort), "--query", "SELECT 1")
		if err == nil && strings.TrimSpace(out) == "1" {
			return
		}
		last = out
		time.Sleep(time.Second)
	}
	logs, _ := dockerOutput(context.Background(), "logs", "--tail", "200", container)
	t.Fatalf("clickhouse did not become ready; last=%s\nlogs:\n%s", last, logs)
}

func dumpClickHouseDiagnostics(t *testing.T, container string) {
	t.Helper()
	if out, err := dockerOutput(context.Background(), "exec", container, "bash", "-lc", "grep -R \"reader\\|ldap\\|podauth\" -n /var/lib/clickhouse/preprocessed_configs /etc/clickhouse-server 2>/dev/null | head -200"); err == nil {
		t.Logf("clickhouse config diagnostics:\n%s", out)
	} else {
		t.Logf("clickhouse config diagnostics failed: %v\n%s", err, out)
	}
	if logs, err := dockerOutput(context.Background(), "logs", "--tail", "200", container); err == nil {
		t.Logf("clickhouse logs:\n%s", logs)
	} else {
		t.Logf("clickhouse logs failed: %v\n%s", err, logs)
	}
	if serverLogs, err := dockerOutput(context.Background(), "exec", container, "bash", "-lc", "ls -la /var/log/clickhouse-server; tail -n 200 /var/log/clickhouse-server/clickhouse-server.log /var/log/clickhouse-server/clickhouse-server.err.log 2>/dev/null || true"); err == nil {
		t.Logf("clickhouse server logs:\n%s", serverLogs)
	} else {
		t.Logf("clickhouse server logs failed: %v\n%s", err, serverLogs)
	}
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tcp listener did not start at %s", addr)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dockerOutput(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func runDocker(ctx context.Context, args ...string) error {
	_, err := dockerOutput(ctx, args...)
	return err
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/dev/urandom")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", buf)
}
