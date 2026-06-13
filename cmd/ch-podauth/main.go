package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rorylshanks/ch-podauth/internal/auth"
	"github.com/rorylshanks/ch-podauth/internal/config"
	"github.com/rorylshanks/ch-podauth/internal/ldapserver"
	"github.com/rorylshanks/ch-podauth/internal/metrics"
	"github.com/rorylshanks/ch-podauth/internal/token"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ch-podauth: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger, err := newLogger(cfg.Logging)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	metricSet := metrics.New()
	validator, err := token.NewOIDCValidator(token.OIDCValidatorConfig{
		Issuer:       cfg.OIDC.Issuer,
		Audience:     cfg.OIDC.Audience,
		ClockSkew:    cfg.OIDC.ClockSkew.Duration,
		JWKSTTL:      cfg.OIDC.JWKSTTL.Duration,
		HTTPTimeout:  cfg.OIDC.HTTPTimeout.Duration,
		MaxJWKSBytes: cfg.OIDC.MaxJWKSBytes,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := validator.Refresh(ctx); err != nil {
		return fmt.Errorf("initial JWKS refresh failed: %w", err)
	}
	logger.Info("initial JWKS refresh complete")

	authService, err := auth.NewService(validator, cfg.AuthMappings(), logger, metricSet)
	if err != nil {
		return err
	}
	ldapServer, err := ldapserver.New(ldapserver.Config{
		ListenAddr:         cfg.LDAP.ListenAddr,
		MaxRequestBytes:    cfg.LDAP.MaxRequestBytes,
		MaxCredentialBytes: cfg.LDAP.MaxCredentialBytes,
		ReadTimeout:        cfg.LDAP.ReadTimeout.Duration,
		WriteTimeout:       cfg.LDAP.WriteTimeout.Duration,
	}, authService, logger, metricSet)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	if cfg.HTTP.ListenAddr != "" {
		httpServer := newHTTPServer(cfg, metricSet)
		go func() {
			logger.Info("http server listening", "addr", cfg.HTTP.ListenAddr)
			err := httpServer.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.Timeout.Duration)
			defer cancel()
			_ = httpServer.Shutdown(shutdownCtx)
		}()
	}
	go func() {
		errCh <- ldapServer.ListenAndServe(ctx)
	}()

	select {
	case <-ctx.Done():
		<-errCh
		return nil
	case err := <-errCh:
		stop()
		if err != nil {
			return err
		}
		return nil
	}
}

func newHTTPServer(cfg config.Config, metricSet *metrics.Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricSet.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return &http.Server{
		Addr:              cfg.HTTP.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.HTTP.Timeout.Duration,
	}
}

func newLogger(cfg config.LoggingConfig) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q", cfg.Level)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(cfg.Format) {
	case "", "json":
		return slog.New(slog.NewJSONHandler(os.Stdout, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stdout, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q", cfg.Format)
	}
}
