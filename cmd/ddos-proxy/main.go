package main

import (
	"context"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
	"github.com/hegy/ddos-proxy/internal/metrics"
	"github.com/hegy/ddos-proxy/internal/proxy"
	"github.com/hegy/ddos-proxy/internal/waf"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

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
	wafManager := waf.NewManager(cfg, rl, tmpl)

	// Start rate limiter reset ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.Reset()
		}
	}()

	reverseProxy := proxy.New(targetURL)
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
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateNew {
				rl.IncConn()
			}
		},
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
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
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
