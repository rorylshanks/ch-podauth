# ch-podauth

`ch-podauth` is a small local LDAP authentication bridge for ClickHouse. ClickHouse performs an LDAP simple bind; the bind name is the ClickHouse user and the bind password is a Kubernetes projected ServiceAccount JWT. The bridge validates the JWT offline against the Kubernetes/EKS OIDC issuer and JWKS, then checks whether that Kubernetes identity is allowed to authenticate as the requested ClickHouse user.

It is intentionally not a general LDAP directory. It implements enough LDAP to answer simple bind requests for ClickHouse authentication.

## Architecture

1. A pod mounts a projected ServiceAccount token with an audience such as `clickhouse-auth`.
2. The application uses that JWT as the ClickHouse password.
3. ClickHouse sends an LDAP simple bind to a local `ch-podauth` listener.
4. `ch-podauth` verifies the JWT signature, issuer, audience, expiry, `nbf`, `iat`, and Kubernetes pod-bound ServiceAccount claims.
5. `ch-podauth` authorizes `namespace/serviceAccount -> ClickHouse username`.
6. LDAP bind success is returned only when validation and authorization both pass.

The service is stateless except for its JWKS cache. It fetches the issuer discovery document, caches JWKS keys, and refreshes them in the background on TTL. On an unknown `kid` it triggers a single refresh so key rotation is picked up without waiting for the TTL; these forced refreshes are single-flighted and rate-limited (`oidc.min_refresh_interval`) so attacker-chosen key ids cannot stampede the JWKS endpoint. If a refresh fails, the last-known-good keys continue to be served so a transient OIDC outage does not take down authentication. The `jwks_uri` advertised by discovery is pinned to the configured issuer's scheme and host.

The validation package is isolated behind a `token.Validator` interface so a future Kubernetes TokenReview validator can be added without changing the LDAP server.

## Build

```sh
go build ./cmd/ch-podauth
```

Docker:

```sh
docker build -t ch-podauth:local .
```

## Run

```sh
cp config.example.yaml config.yaml
CH_PODAUTH_CONFIG=config.yaml ./ch-podauth
```

Common environment overrides:

```sh
CH_PODAUTH_LDAP_ADDR=127.0.0.1:1389
CH_PODAUTH_HTTP_ADDR=127.0.0.1:8080
CH_PODAUTH_OIDC_ISSUER=https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE
CH_PODAUTH_AUDIENCE=clickhouse-auth
```

Mappings can also be supplied as JSON:

```sh
CH_PODAUTH_MAPPINGS='[{"namespace":"analytics","service_account":"clickhouse-reader","clickhouse_users":["reader"]}]'
```

## HTTP Endpoints

The HTTP listener (`http.listen_addr`, default `127.0.0.1:8080`) serves two routes:

- `GET /healthz` — liveness/readiness probe, returns `200 ok`.
- `GET /metrics` — Prometheus metrics (via `prometheus/client_golang`).

Exported metrics include:

| Metric | Type | Notes |
| --- | --- | --- |
| `ch_podauth_ldap_binds_total` | counter | All bind attempts. |
| `ch_podauth_ldap_bind_success_total` | counter | Authenticated and authorized binds. |
| `ch_podauth_ldap_bind_failure_total` | counter | Denied binds. |
| `ch_podauth_ldap_bind_failures_by_reason_total` | counter | Denials by `reason` label. |
| `ch_podauth_bind_duration_seconds` | histogram | Bind authentication latency (token validation + authz). |
| `ch_podauth_ldap_request_too_large_total` | counter | Requests/credentials over the size limits. |
| `ch_podauth_ldap_protocol_errors_total` | counter | Unparseable LDAP requests. |
| `ch_podauth_ldap_connections_rejected_total` | counter | Connections rejected at the concurrency limit. |
| `ch_podauth_active_connections` | gauge | LDAP connections currently served. |
| `ch_podauth_max_connections` | gauge | Configured connection limit. |
| `ch_podauth_jwks_refresh_total` | counter | JWKS refreshes by `result` (success/failure). |
| `ch_podauth_jwks_last_success_timestamp_seconds` | gauge | Time of the last successful refresh. |
| `ch_podauth_jwks_keys` | gauge | Usable keys currently cached. |

Standard `go_*` and `process_*` runtime metrics are exported as well.

## ClickHouse Config

Place the LDAP server in ClickHouse `config.d`:

```xml
<clickhouse>
  <ldap_servers>
    <podauth>
      <host>127.0.0.1</host>
      <port>1389</port>
      <enable_tls>no</enable_tls>
      <bind_dn>{user_name}</bind_dn>
      <verification_cooldown>0</verification_cooldown>
    </podauth>
  </ldap_servers>
</clickhouse>
```

Place LDAP-authenticated users in `users.d`:

```xml
<clickhouse>
  <users>
    <reader>
      <ldap>
        <server>podauth</server>
      </ldap>
      <profile>default</profile>
      <quota>default</quota>
    </reader>
  </users>
</clickhouse>
```

For production, bind `ch-podauth` to localhost on each ClickHouse node and protect the ClickHouse native TCP connection with your normal network controls or TLS.

## Kubernetes Projected Token

Example pod volume:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: clickhouse-client
  namespace: analytics
spec:
  serviceAccountName: clickhouse-reader
  containers:
    - name: app
      image: example/app:latest
      volumeMounts:
        - name: clickhouse-token
          mountPath: /var/run/secrets/clickhouse
          readOnly: true
      env:
        - name: CLICKHOUSE_PASSWORD_FILE
          value: /var/run/secrets/clickhouse/token
  volumes:
    - name: clickhouse-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: clickhouse-auth
              expirationSeconds: 3600
```

The JWT must contain Kubernetes pod-bound claims under `kubernetes.io`, including namespace, service account name and UID, pod name, and pod UID. Tokens without pod binding are rejected even if their signature is valid.

## Security Model

`ch-podauth` fails closed:

- It rejects missing or unexpected issuer and audience claims.
- It requires normal JWT validity checks: signature, `exp`, `nbf`, and future `iat` handling.
- It requires pod-bound projected ServiceAccount identity claims.
- It rejects oversized LDAP requests and oversized bind credentials, and bounds the number of concurrent LDAP connections (`ldap.max_connections`).
- It pins the discovery `jwks_uri` to the issuer host and rate-limits forced JWKS refreshes to avoid amplification against the OIDC endpoint.
- It never logs the JWT or bind password.
- Logs may include namespace, service account, pod name, ClickHouse username, decision, and a short SHA-256 token fingerprint.
- It does not call the Kubernetes API in this version, so it does not prove current pod liveness after token issuance.

Offline validation is appropriate when you want a local, low-latency, API-independent auth bridge. A TokenReview validator can be added later when stricter liveness checks are worth the Kubernetes API dependency.

## Tests

Unit tests:

```sh
go test ./...
```

Docker/ClickHouse e2e test:

```sh
go test -tags=e2e ./e2e -run TestClickHouseLDAPBridge -count=1 -v
```

The e2e test starts a ClickHouse container and configures ClickHouse itself to dynamic non-default HTTP, native TCP, and interserver ports, so it can run on a host that already has ClickHouse bound to `8123`, `9000`, or `9009`.
