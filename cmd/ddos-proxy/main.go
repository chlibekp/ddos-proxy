package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
	"github.com/hegy/ddos-proxy/internal/metrics"
	"github.com/hegy/ddos-proxy/internal/proxy"
	"github.com/hegy/ddos-proxy/internal/waf"
	"github.com/hegy/ddos-proxy/internal/xdp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	stdLogger := log.New(logWriter{}, "", 0)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", "PROXY_BACKEND_URL is required")
		os.Exit(1)
	}

	// Parse the backend URL.
	targetURL, err := url.Parse(cfg.BackendURL)
	if err != nil {
		slog.Error("Invalid backend URL", "url", cfg.BackendURL, "error", err)
		os.Exit(1)
	}

	// Load templates
	tmpl, err := template.ParseFiles("challenge.html")
	if err != nil {
		slog.Error("Failed to load templates", "error", err)
		os.Exit(1)
	}

	rl := limiter.New()

	var xdpBlocker xdp.Blocker
	if cfg.XDPInterface != "" {
		slog.Info("Initializing XDP blocker", "interface", cfg.XDPInterface)
		blocker, err := xdp.InitXDP(cfg.XDPInterface)
		if err != nil {
			slog.Error("Failed to initialize XDP", "error", err)
			os.Exit(1)
		}
		defer blocker.Close()
		xdpBlocker = blocker

		// Start a goroutine to print XDP stats every second
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			var prevAllowed, prevBlocked uint64
			// Initialize with current stats to avoid huge spikes if XDP was already running
			if initialStats, err := blocker.GetStats(); err == nil {
				prevAllowed = initialStats.Allowed
				prevBlocked = initialStats.Blocked
			}

			for range ticker.C {
				stats, err := blocker.GetStats()
				if err == nil {
					var deltaAllowed, deltaBlocked uint64
					if stats.Allowed >= prevAllowed {
						deltaAllowed = stats.Allowed - prevAllowed
					} else {
						// eBPF counters reset
						deltaAllowed = stats.Allowed
					}

					if stats.Blocked >= prevBlocked {
						deltaBlocked = stats.Blocked - prevBlocked
					} else {
						deltaBlocked = stats.Blocked
					}

					if deltaAllowed > 0 || deltaBlocked > 0 {
						slog.Info("XDP Stats (per sec)", "ALLOWED", deltaAllowed, "BLOCKED", deltaBlocked)
					}

					if cfg.PrometheusEnabled {
						if deltaAllowed > 0 {
							metrics.XDPPackets.WithLabelValues("allowed").Add(float64(deltaAllowed))
						}
						if deltaBlocked > 0 {
							metrics.XDPPackets.WithLabelValues("blocked").Add(float64(deltaBlocked))
						}
					}
					prevAllowed = stats.Allowed
					prevBlocked = stats.Blocked
				} else {
					slog.Error("Failed to get XDP stats", "error", err)
				}
			}
		}()
	} else {
		slog.Info("XDP blocking is disabled (PROXY_XDP_INTERFACE not set)")
	}

	wafManager := waf.NewManager(cfg, rl, tmpl, xdpBlocker)

	// Start rate limiter reset ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.Reset()
		}
	}()

	reverseProxy := proxy.New(targetURL, cfg)
	handler := wafManager.Middleware(reverseProxy)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	if cfg.PrometheusEnabled {
		metricsLimiter := limiter.NewIPLimiter()
		metricsHandler := promhttp.Handler()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if !metricsLimiter.Allow(ip) {
				metrics.DroppedRequests.WithLabelValues("metrics_rate_limit").Inc()
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			metricsHandler.ServeHTTP(w, r)
		})
		slog.Info("Prometheus metrics enabled", "endpoint", "/metrics")
	}

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     stdLogger,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateNew {
				rl.IncConn()
			}
		},
	}

	if cfg.EnableSSL {
		// Ensure the certs directory exists
		if err := os.MkdirAll("certs", 0700); err != nil {
			slog.Error("Failed to create certs directory", "error", err)
			os.Exit(1)
		}

		m := &autocert.Manager{
			Cache:  autocert.DirCache("certs"),
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				slog.Info("ACME host policy check started", "host", host, "backend", cfg.BackendURL)
				req, err := http.NewRequestWithContext(ctx, "GET", cfg.BackendURL+"/", nil)
				if err != nil {
					slog.Error("ACME host policy request creation failed", "host", host, "error", err)
					return err
				}
				req.Host = host

				client := &http.Client{
					Timeout: 5 * time.Second,
				}
				resp, err := client.Do(req)
				if err != nil {
					slog.Error("ACME host policy backend probe failed", "host", host, "backend", cfg.BackendURL, "error", err)
					return err
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					err := fmt.Errorf("backend did not respond with 200 OK on root, got %d", resp.StatusCode)
					slog.Error("ACME host policy rejected host", "host", host, "backend", cfg.BackendURL, "status_code", resp.StatusCode, "error", err)
					return err
				}
				slog.Info("ACME host policy approved host", "host", host, "backend", cfg.BackendURL, "status_code", resp.StatusCode)
				return nil
			},
		}
		if cfg.ACMEStaging {
			m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
			slog.Warn("ACME staging is enabled; issued certificates will not be trusted by browsers")
		}
		tlsConfig := m.TLSConfig()
		origGetCertificate := tlsConfig.GetCertificate
		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			remoteAddr := clientHelloRemoteAddr(hello)
			slog.Info("TLS certificate request received",
				"server_name", hello.ServerName,
				"remote_addr", remoteAddr,
				"supported_protos", hello.SupportedProtos,
			)

			cert, err := origGetCertificate(hello)
			if err != nil {
				slog.Error("TLS certificate request failed",
					"server_name", hello.ServerName,
					"remote_addr", remoteAddr,
					"error", err,
				)
				return nil, err
			}

			slog.Info("TLS certificate request succeeded",
				"server_name", hello.ServerName,
				"remote_addr", remoteAddr,
			)
			return cert, nil
		}
		server.TLSConfig = tlsConfig

		// Start HTTP redirect server for Let's Encrypt HTTP-01 challenges and HTTPS redirection
		go func() {
			redirectHandler := m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				slog.Info("HTTP redirect request received", "host", r.Host, "path", r.URL.Path, "target", target, "remote_addr", r.RemoteAddr)
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))

			redirectSrv := &http.Server{
				Addr: ":" + cfg.HTTPPort,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
						slog.Info("ACME HTTP-01 challenge request received", "host", r.Host, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
					}
					redirectHandler.ServeHTTP(w, r)
				}),
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
				ErrorLog:     stdLogger,
			}

			slog.Info("Starting HTTP to HTTPS redirect server", "port", cfg.HTTPPort)
			if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP redirect server failed", "error", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Starting proxy server",
			"port", cfg.Port,
			"backend", cfg.BackendURL,
			"max_req_per_sec", cfg.MaxReqPerSec,
			"max_conn_per_sec", cfg.MaxConnPerSec,
			"mitigation_time", cfg.MitigationTime,
			"always_on", cfg.AlwaysOn,
			"prometheus_enabled", cfg.PrometheusEnabled,
			"ssl_enabled", cfg.EnableSSL,
			"acme_staging", cfg.ACMEStaging,
		)
		if cfg.EnableSSL {
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("Server failed", "error", err)
				os.Exit(1)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Server failed", "error", err)
				os.Exit(1)
			}
		}
	}()

	<-stop
	slog.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited properly")
}

type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if msg != "" {
		slog.Error("HTTP server internal log", "message", msg)
	}
	return len(p), nil
}

func clientHelloRemoteAddr(hello *tls.ClientHelloInfo) string {
	if hello == nil || hello.Conn == nil || hello.Conn.RemoteAddr() == nil {
		return ""
	}
	return hello.Conn.RemoteAddr().String()
}
