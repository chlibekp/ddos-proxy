package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gregjones/httpcache"
	"github.com/gregjones/httpcache/diskcache"
	"github.com/hegy/ddos-proxy/internal/config"
)

// NormalizingTransport wraps an http.RoundTripper to fix malformed Cache-Control headers
type NormalizingTransport struct {
	Transport http.RoundTripper
}

func (n *NormalizingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := n.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// The httpcache library uses headers.Get("Cache-Control"), which only returns the FIRST
	// Cache-Control header if there are multiple. We need to merge them into one.
	if ccHeaders, ok := resp.Header["Cache-Control"]; ok && len(ccHeaders) > 0 {
		merged := strings.Join(ccHeaders, ", ")

		// Some backends return malformed headers like "max-age 86400" instead of "max-age=86400"
		// The httpcache library expects the strict RFC format with equals signs.
		re := regexp.MustCompile(`(max-age|s-maxage)\s+(\d+)`)
		merged = re.ReplaceAllString(merged, "$1=$2")

		resp.Header.Set("Cache-Control", merged)
	}

	return resp, nil
}

// New creates a new reverse proxy handler for the given target URL.
// It includes logic for header manipulation and JS injection for mitigation checks.
func New(target *url.URL, cfg *config.Config) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	if cfg.CacheEnabled {
		cacheDir := "/tmp/ddos-mitigator-cache"
		slog.Info("Enabling disk cache", "dir", cacheDir)
		cache := diskcache.New(cacheDir)

		// Create a custom transport that normalizes Cache-Control headers before passing to httpcache
		baseTransport := http.DefaultTransport

		normalizedTransport := &NormalizingTransport{
			Transport: baseTransport,
		}

		transport := httpcache.NewTransport(cache)
		transport.Transport = normalizedTransport
		proxy.Transport = transport
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		originalDirector(req)
		req.Host = originalHost

		// Disable compression so we can inspect body
		req.Header.Del("Accept-Encoding")

		// Set X-Forwarded-Host if not present
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", originalHost)
		}
		// Set X-Forwarded-Proto if not present
		if req.Header.Get("X-Forwarded-Proto") == "" {
			scheme := "http"
			if req.TLS != nil {
				scheme = "https"
			}
			req.Header.Set("X-Forwarded-Proto", scheme)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// Add Via header for clean traffic identification
		resp.Header.Set("Via", "ddos-mitigator")

		// Handle cache status header
		if cfg.CacheEnabled {
			if resp.Header.Get("X-From-Cache") == "1" {
				resp.Header.Set("X-Ddos-Mitigator-Cache", "HIT")
				resp.Header.Del("X-From-Cache")
			} else {
				// If it's not from cache, but Cache-Control allows caching, it's a MISS.
				// Otherwise, it's DYNAMIC.
				cc := resp.Header.Get("Cache-Control")
				if cc != "" && !strings.Contains(cc, "no-cache") && !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") {
					resp.Header.Set("X-Ddos-Mitigator-Cache", "MISS")
				} else {
					resp.Header.Set("X-Ddos-Mitigator-Cache", "DYNAMIC")
				}
			}
		} else {
			resp.Header.Set("X-Ddos-Mitigator-Cache", "DYNAMIC")
		}

		// Inject JS to check for X-Mitigation header
		contentType := resp.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "text/html") {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()

			// JS to check X-Mitigation header
			// This script intercepts fetch and XMLHttpRequest to check for mitigation headers
			js := `<script>(function(){var r=function(){window.location.reload()};var c=function(h){if(h==='challenge')r()};var f=window.fetch;if(f){window.fetch=function(){return f.apply(this,arguments).then(function(res){if(res&&res.headers&&res.headers.get){c(res.headers.get('X-Mitigation'))}return res})}}var x=XMLHttpRequest.prototype;var o=x.open;x.open=function(){this.addEventListener('load',function(){if(this.getResponseHeader){c(this.getResponseHeader('X-Mitigation'))}});return o.apply(this,arguments)};if(window.fetch){document.addEventListener('error',function(e){var t=e.target;if(t&&t.tagName&&(t.src||t.href)){var g=t.tagName;if(g==='IMG'||g==='SCRIPT'||g==='LINK'||g==='IFRAME'||g==='VIDEO'||g==='AUDIO'){var u=t.src||t.href;if(u&&u.indexOf('data:')!==0){window.fetch(u,{method:'HEAD'}).catch(function(){})}}}},true)}})();</script>`

			bodyStr := string(bodyBytes)
			if strings.Contains(bodyStr, "<head>") {
				bodyStr = strings.Replace(bodyStr, "<head>", "<head>"+js, 1)
			} else if strings.Contains(bodyStr, "<body>") {
				bodyStr = strings.Replace(bodyStr, "<body>", "<body>"+js, 1)
			} else {
				bodyStr = js + bodyStr
			}

			resp.Body = io.NopCloser(strings.NewReader(bodyStr))
			resp.ContentLength = int64(len(bodyStr))
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyStr)))
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return nil
		}

		locURL, err := url.Parse(location)
		if err != nil {
			return nil
		}

		// If the redirect location host matches the backend target host,
		// rewrite it to the original request host.
		if locURL.Host == target.Host {
			locURL.Host = resp.Request.Host

			// Attempt to preserve the scheme from X-Forwarded-Proto
			scheme := resp.Request.Header.Get("X-Forwarded-Proto")
			if scheme == "" {
				if resp.Request.TLS != nil {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}
			locURL.Scheme = scheme

			resp.Header.Set("Location", locURL.String())
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("Proxy error", "error", err, "path", r.URL.Path)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return proxy
}
