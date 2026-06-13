package ldapserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rorylshanks/ch-podauth/internal/auth"
	"github.com/rorylshanks/ch-podauth/internal/metrics"
)

type Config struct {
	ListenAddr         string
	MaxRequestBytes    int
	MaxCredentialBytes int
	MaxConnections     int
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
}

type Server struct {
	cfg     Config
	auth    *auth.Service
	logger  *slog.Logger
	metrics *metrics.Metrics

	listener net.Listener
	wg       sync.WaitGroup
	sem      chan struct{}
}

func New(cfg Config, authService *auth.Service, logger *slog.Logger, metrics *metrics.Metrics) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:1389"
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = 128 * 1024
	}
	if cfg.MaxCredentialBytes == 0 {
		cfg.MaxCredentialBytes = 32 * 1024
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 256
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if authService == nil {
		return nil, errors.New("auth service is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if metrics != nil {
		metrics.SetMaxConnections(cfg.MaxConnections)
	}
	return &Server{
		cfg:     cfg,
		auth:    authService,
		logger:  logger,
		metrics: metrics,
		sem:     make(chan struct{}, cfg.MaxConnections),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.logger.Info("ldap server listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			s.logger.Error("accept ldap connection", "error", err)
			continue
		}
		// Bound concurrent connections so an unbounded number of clients cannot
		// exhaust goroutines/file descriptors. Reject quickly when at capacity.
		select {
		case s.sem <- struct{}{}:
		default:
			if s.metrics != nil {
				s.metrics.ObserveConnectionRejected()
			}
			s.logger.Warn("ldap connection rejected", "reason", "max_connections", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handleConnection(ctx, conn)
		}()
	}
}

func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) handleConnection(parent context.Context, conn net.Conn) {
	defer conn.Close()
	if s.metrics != nil {
		s.metrics.IncActiveConnections()
		defer s.metrics.DecActiveConnections()
	}
	remote := conn.RemoteAddr().String()
	reader := bufio.NewReaderSize(conn, min(s.cfg.MaxRequestBytes, 64*1024))

	for {
		if s.cfg.ReadTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
		}
		msg, err := readMessage(reader, s.cfg.MaxRequestBytes)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			if errors.Is(err, errRequestLarge) {
				if s.metrics != nil {
					s.metrics.ObserveRequestTooLarge()
				}
				s.logger.Warn("ldap request too large", "remote", remote)
				return
			}
			if s.metrics != nil {
				s.metrics.ObserveProtocolError()
			}
			s.logger.Warn("ldap protocol error", "remote", remote, "error", err)
			return
		}

		switch req := msg.Op.(type) {
		case bindRequest:
			s.handleBind(parent, conn, msg.ID, req, remote)
		case unbindRequest:
			return
		case unsupportedRequest:
			s.writeResponse(conn, encodeLDAPBindResponse(msg.ID, ldapResultUnwillingToPerform, "unsupported LDAP operation"))
			s.logger.Warn("unsupported ldap operation", "remote", remote, "tag", req.Tag)
		default:
			s.writeResponse(conn, encodeLDAPBindResponse(msg.ID, ldapResultProtocolError, "protocol error"))
		}
	}
}

func (s *Server) handleBind(parent context.Context, conn net.Conn, messageID int, req bindRequest, remote string) {
	if req.Version != 3 {
		s.writeResponse(conn, encodeLDAPBindResponse(messageID, ldapResultProtocolError, "only LDAPv3 is supported"))
		return
	}
	if len(req.Password) > s.cfg.MaxCredentialBytes {
		if s.metrics != nil {
			s.metrics.ObserveRequestTooLarge()
			s.metrics.ObserveBind(false, "credential_too_large")
		}
		s.logger.Warn("ldap bind denied", "reason", "credential_too_large", "clickhouse_user", req.Username, "remote", remote)
		s.writeResponse(conn, encodeLDAPBindResponse(messageID, ldapResultInvalidCredentials, "invalid credentials"))
		return
	}

	ctx, cancel := context.WithTimeout(parent, s.cfg.ReadTimeout)
	defer cancel()
	start := time.Now()
	decision := s.auth.Authenticate(ctx, req.Username, req.Password)
	if s.metrics != nil {
		s.metrics.ObserveBindDuration(time.Since(start).Seconds())
	}
	if decision.Allowed {
		s.writeResponse(conn, encodeLDAPBindResponse(messageID, ldapResultSuccess, ""))
		return
	}
	s.writeResponse(conn, encodeLDAPBindResponse(messageID, ldapResultInvalidCredentials, "invalid credentials"))
}

func (s *Server) writeResponse(conn net.Conn, data []byte) {
	if s.cfg.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	}
	if _, err := conn.Write(data); err != nil {
		s.logger.Warn("write ldap response", "error", err)
	}
}
