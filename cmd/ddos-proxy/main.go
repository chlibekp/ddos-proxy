package main

import (
	"context"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	texttemplate "text/template"
	"time"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
	"github.com/hegy/ddos-proxy/internal/metrics"
	"github.com/hegy/ddos-proxy/internal/proxy"
	"github.com/hegy/ddos-proxy/internal/waf"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const vclTemplateStr = `
vcl 4.1;

backend default {
    .host = "{{ .Host }}";
    .port = "{{ .Port }}";
}

sub vcl_recv {
    # Ignore client cache-control headers so they don't force cache bypass
    unset req.http.Cache-Control;
    unset req.http.Pragma;

{{ if not .CacheEnabled }}
    return (pass);
{{ else }}
    # Varnish's default behavior is to bypass the cache entirely if it sees a Cookie or Authorization header.
    # We force it to hash GET/HEAD requests so we can inspect the backend's Cache-Control header in vcl_backend_response.
    if (req.method == "GET" || req.method == "HEAD") {
        return (hash);
    }
{{ end }}
}

sub vcl_pass {
    set req.http.X-Ddos-Dynamic = "1";
}

sub vcl_backend_fetch {
    unset bereq.http.X-Ddos-Dynamic;
}

sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }
    return (lookup);
}

sub vcl_backend_response {
    # If the backend explicitly marks the response as public, cache it!
    if (beresp.http.Cache-Control ~ "public") {
        # Remove Set-Cookie to prevent caching someone's session cookie
        unset beresp.http.Set-Cookie;
        return (deliver);
    }

    # If it's NOT public, revert to Varnish's standard safe behavior:
    # Do not cache if the request had Cookies/Auth or the response sets a Cookie
    if (bereq.http.Cookie || bereq.http.Authorization || beresp.http.Set-Cookie || beresp.http.Cache-Control ~ "private|no-cache|no-store") {
        set beresp.uncacheable = true;
        return (deliver);
    }
}

sub vcl_deliver {
    if (req.http.X-Ddos-Dynamic == "1") {
        set resp.http.X-Ddos-Mitigator-Cache = "DYNAMIC";
    } else if (obj.hits > 0) {
        set resp.http.X-Ddos-Mitigator-Cache = "HIT";
    } else {
        set resp.http.X-Ddos-Mitigator-Cache = "MISS";
    }
}
`

type VCLConfig struct {
	Host         string
	Port         string
	CacheEnabled bool
}

func startVarnish(backendURL *url.URL, cacheEnabled bool) error {
	host := backendURL.Hostname()
	port := backendURL.Port()
	if port == "" {
		if backendURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	tmpl, err := texttemplate.New("vcl").Parse(vclTemplateStr)
	if err != nil {
		return err
	}

	f, err := os.Create("/tmp/default.vcl")
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tmpl.Execute(f, VCLConfig{Host: host, Port: port, CacheEnabled: cacheEnabled}); err != nil {
		return err
	}

	cmd := exec.Command("varnishd", "-f", "/tmp/default.vcl", "-a", ":8081", "-s", "malloc,256m", "-F")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	go func() {
		if err := cmd.Run(); err != nil {
			slog.Error("varnishd exited with error", "error", err)
		}
	}()

	// Wait for Varnish to start
	time.Sleep(2 * time.Second)
	return nil
}

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

	err = startVarnish(targetURL, cfg.VarnishEnabled)
	if err != nil {
		slog.Error("Failed to start varnish", "error", err)
		os.Exit(1)
	}

	// Update the proxyURL to point to Varnish
	proxyURL, _ := url.Parse("http://127.0.0.1:8081")

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

	reverseProxy := proxy.New(proxyURL, targetURL)
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
