package waf

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
	"github.com/hegy/ddos-proxy/internal/metrics"
	"github.com/hegy/ddos-proxy/internal/xdp"
)

// Manager holds the application state and protection logic.
type Manager struct {
	cfg             *config.Config
	rl              *limiter.RateLimiter
	templates       *template.Template
	xdp             xdp.Blocker
	mitigationUntil int64    // Atomic unix timestamp
	timeoutCount    int64    // Atomic counter for long/timed-out requests
	ipStates        sync.Map // map[string]*ClientState
}

// ChallengeData is passed to the template.
type ChallengeData struct {
	Error         string
	SiteKey       string
	OriginalURL   string
	PoWSalt       string
	PoWDifficulty int
}

// NewManager creates a new WAF manager.
func NewManager(cfg *config.Config, rl *limiter.RateLimiter, tmpl *template.Template, xdpBlocker xdp.Blocker) *Manager {
	manager := &Manager{
		cfg:       cfg,
		rl:        rl,
		templates: tmpl,
		xdp:       xdpBlocker,
	}

	// Start cleanup ticker
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			manager.cleanup()
		}
	}()

	return manager
}

func (m *Manager) getClientIP(r *http.Request) string {
	if m.cfg.CloudflareSupport {
		cfIP := r.Header.Get("CF-Connecting-IP")
		if cfIP != "" {
			return cfIP
		}
	}

	if m.cfg.UseForwardedFor {
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			// X-Forwarded-For: client, proxy1, proxy2
			ips := strings.Split(forwarded, ",")
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If RemoteAddr doesn't have port (e.g. unit tests or special listeners), use it as is
		return r.RemoteAddr
	}
	return ip
}

func (m *Manager) verifyTurnstile(responseToken, remoteIP string) bool {
	formData := url.Values{}
	formData.Set("secret", m.cfg.TurnstileSecretKey)
	formData.Set("response", responseToken)
	formData.Set("remoteip", remoteIP)

	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", formData)
	if err != nil {
		slog.Error("Turnstile verification failed", "error", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		slog.Error("Failed to decode Turnstile response", "error", err)
		return false
	}
	return result.Success
}

func (m *Manager) serveChallenge(w http.ResponseWriter, r *http.Request, errMsg string) {
	ip := m.getClientIP(r)
	state := m.getClientState(ip, r.Host)

	state.mu.Lock()
	if state.powSalt == "" {
		b := make([]byte, 16)
		rand.Read(b)
		state.powSalt = hex.EncodeToString(b)
	}
	state.challengeServedAt = time.Now()
	salt := state.powSalt
	state.mu.Unlock()

	data := ChallengeData{
		Error:         errMsg,
		SiteKey:       m.cfg.TurnstileSiteKey,
		OriginalURL:   r.URL.String(),
		PoWSalt:       salt,
		PoWDifficulty: m.cfg.PoWDifficulty,
	}

	w.Header().Set("X-Mitigation", "challenge")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusTeapot)
	m.templates.Execute(w, data)

	// Increment challenged requests metric
	if m.cfg.PrometheusEnabled {
		metrics.ChallengedRequests.Inc()
	}
}

func (m *Manager) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		if m.cfg.PrometheusEnabled {
			metrics.DroppedRequests.WithLabelValues("challenge_invalid_form").Inc()
		}
		m.serveChallenge(w, r, "Invalid form data")
		return
	}

	ip := m.getClientIP(r)

	if m.cfg.TurnstileSiteKey != "" {
		// Turnstile Verification
		responseToken := r.FormValue("cf-turnstile-response")
		if responseToken == "" {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_empty_token").Inc()
			}
			m.serveChallenge(w, r, "Please complete the CAPTCHA")
			return
		}
		if !m.verifyTurnstile(responseToken, ip) {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_verification_failed").Inc()
			}
			m.serveChallenge(w, r, "CAPTCHA verification failed")
			return
		}
	} else {
		// PoW Verification
		nonce := r.FormValue("pow_nonce")
		if nonce == "" {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_empty_pow").Inc()
			}
			m.serveChallenge(w, r, "Please complete the PoW")
			return
		}

		state := m.getClientState(ip, r.Host)
		state.mu.Lock()
		salt := state.powSalt
		servedAt := state.challengeServedAt
		state.mu.Unlock()

		if salt == "" {
			m.serveChallenge(w, r, "Invalid challenge session")
			return
		}

		if time.Since(servedAt) < 2*time.Second {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_too_fast").Inc()
			}
			m.serveChallenge(w, r, "Challenge solved too quickly, please try again")
			return
		}

		hash := sha256.Sum256([]byte(salt + nonce))
		hashHex := hex.EncodeToString(hash[:])
		targetPrefix := strings.Repeat("0", m.cfg.PoWDifficulty)
		if !strings.HasPrefix(hashHex, targetPrefix) {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_pow_failed").Inc()
			}
			m.serveChallenge(w, r, "PoW verification failed")
			return
		}
	}

	// Mark IP as verified
	state := m.getClientState(ip, r.Host)
	state.mu.Lock()
	state.violationCount = 0
	state.challengeServed = false
	state.blocked = false
	state.verified = true
	state.verifiedAt = time.Now()
	// Clear PoW salt so it can't be reused
	state.powSalt = ""
	state.mu.Unlock()

	// Redirect to original URL
	originalURL := r.FormValue("original_url")
	if originalURL == "" {
		originalURL = "/"
	}

	if m.cfg.PrometheusEnabled {
		metrics.AllowedRequests.WithLabelValues("challenge_solved").Inc()
	}

	http.Redirect(w, r, originalURL, http.StatusFound)
}

func (m *Manager) blockL4(ip string) {
	if m.xdp == nil {
		return
	}
	slog.Info("Blocking IP on L4 via XDP", "ip", ip)
	if err := m.xdp.BlockIP(ip); err != nil {
		slog.Error("Failed to add XDP block rule", "ip", ip, "error", err)
	}
}

func (m *Manager) unblockL4(ip string) {
	if m.xdp == nil {
		return
	}
	slog.Info("Unblocking IP on L4 via XDP", "ip", ip)
	if err := m.xdp.UnblockIP(ip); err != nil {
		slog.Error("Failed to remove XDP block rule", "ip", ip, "error", err)
	}
}

func (m *Manager) getClientState(ip, host string) *ClientState {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // Might not have a port
	}
	key := ip + "|" + h

	val, ok := m.ipStates.Load(key)
	if ok {
		return val.(*ClientState)
	}
	state := &ClientState{
		lastSeen: time.Now(),
	}
	actual, loaded := m.ipStates.LoadOrStore(key, state)
	if loaded {
		return actual.(*ClientState)
	}
	return state
}

func (m *Manager) cleanup() {
	now := time.Now()
	mitigationEnd := time.Unix(atomic.LoadInt64(&m.mitigationUntil), 0)
	attackEnded := now.After(mitigationEnd)

	// Reset timeout count every cleanup cycle
	atomic.StoreInt64(&m.timeoutCount, 0)

	// If attack has ended and we are not in always-on mode, we can be more aggressive with cleanup
	// But we still need to iterate to check blocked IPs expiration

	m.ipStates.Range(func(key, value interface{}) bool {
		state := value.(*ClientState)
		state.mu.Lock()
		defer state.mu.Unlock()

		// Expire verification
		if state.verified && now.Sub(state.verifiedAt) > m.cfg.VerifyTime {
			state.verified = false
		}

		// If attack ended and not always on, we can clear non-verified states
		if attackEnded && !m.cfg.AlwaysOn && !state.verified {
			m.ipStates.Delete(key)
			return true
		}

		// Unblock if blocked for more than 5 minutes
		if state.blocked && now.Sub(state.blockedAt) > 5*time.Minute {
			state.blocked = false
			state.violationCount = 0
			state.challengeServed = false
			state.errorCount = 0
			if state.l4Blocked {
				state.l4Blocked = false
				parts := strings.Split(key.(string), "|")
				if len(parts) > 0 {
					go m.unblockL4(parts[0])
				}
			}
		}

		// Cleanup idle connections (e.g. 10 min inactivity)
		// If verified, we keep it. If not verified and idle, delete.
		if !state.verified && now.Sub(state.lastSeen) > 10*time.Minute {
			m.ipStates.Delete(key)
		}

		return true
	})
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") &&
		strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
}

// Middleware is the main entry point for the WAF protection.
// It checks rate limits, IP blocking, and serves challenges if necessary.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass WAF entirely for WebSocket upgrades so they always work
		if isWebSocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Check Whitelisted User Agents
		ua := r.Header.Get("User-Agent")
		isWhitelisted := false
		if len(m.cfg.WhitelistedUA) > 0 {
			for _, wua := range m.cfg.WhitelistedUA {
				if strings.Contains(ua, wua) {
					isWhitelisted = true
					break
				}
			}
		}

		if isWhitelisted {
			current := m.rl.GetWhitelistReqCount()
			if current >= m.cfg.WhitelistRateLimit {
				if m.cfg.PrometheusEnabled {
					metrics.DroppedRequests.WithLabelValues("whitelist_rate_limit").Inc()
				}
				http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
				return
			}
			m.rl.IncWhitelistReq()
			if m.cfg.PrometheusEnabled {
				metrics.AllowedRequests.WithLabelValues("whitelist").Inc()
			}
			next.ServeHTTP(w, r)
			return
		}

		ip := m.getClientIP(r)

		// Check if IP is blocked
		state := m.getClientState(ip, r.Host)
		state.mu.Lock()
		state.lastSeen = time.Now()
		if state.blocked {
			// Handle L4 blocking if Cloudflare and ForwardedFor are not used
			if !m.cfg.CloudflareSupport && !m.cfg.UseForwardedFor {
				if !state.l4Blocked {
					state.errorCount++
					if state.errorCount > 5 {
						state.l4Blocked = true
						go m.blockL4(ip)
						state.mu.Unlock()
						// L4 blocked, close connection immediately as fallback before iptables takes effect
						if hijacker, ok := w.(http.Hijacker); ok {
							if conn, _, err := hijacker.Hijack(); err == nil {
								conn.Close()
							}
						}
						return
					}
				} else {
					// Already L4 blocked, connection should have been dropped by iptables
					// Fallback: close connection immediately
					state.mu.Unlock()
					if hijacker, ok := w.(http.Hijacker); ok {
						if conn, _, err := hijacker.Hijack(); err == nil {
							conn.Close()
						}
					}
					return
				}
			}

			state.mu.Unlock()
			// Hijack and close connection or send 403
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("blocked_ip").Inc()
			}
			if m.cfg.BlockAction == "close" {
				if hijacker, ok := w.(http.Hijacker); ok {
					conn, _, err := hijacker.Hijack()
					if err == nil {
						conn.Close()
					}
				} else {
					http.Error(w, "Forbidden", http.StatusForbidden)
				}
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
			return
		}

		// Check verification status
		if state.verified {
			// Check expiration
			if time.Since(state.verifiedAt) < m.cfg.VerifyTime {
				state.mu.Unlock()
				if m.cfg.PrometheusEnabled {
					metrics.AllowedRequests.WithLabelValues("verified").Inc()
				}
				next.ServeHTTP(w, r)
				return
			}
			// Expired
			state.verified = false
		}
		state.mu.Unlock()

		// Bypass for challenge verification
		if r.URL.Path == "/challenge/verify" {
			m.verifyChallenge(w, r)
			return
		}

		// Check global rate limits
		reqRate, connRate := m.rl.GetCounts()
		now := time.Now().Unix()
		mitigationUntil := atomic.LoadInt64(&m.mitigationUntil)

		// Determine if we should serve challenge
		shouldServeChallenge := m.cfg.AlwaysOn

		// If limits exceeded, extend mitigation time and enable challenge
		if reqRate >= m.cfg.MaxReqPerSec || connRate >= m.cfg.MaxConnPerSec {
			newUntil := time.Now().Add(m.cfg.MitigationTime).Unix()
			atomic.StoreInt64(&m.mitigationUntil, newUntil)
			shouldServeChallenge = true
		} else if now < mitigationUntil {
			shouldServeChallenge = true
		} else if m.cfg.AutoMitigationOnTimeout {
			if atomic.LoadInt64(&m.timeoutCount) >= int64(m.cfg.MaxTimeouts) {
				newUntil := time.Now().Add(m.cfg.MitigationTime).Unix()
				atomic.StoreInt64(&m.mitigationUntil, newUntil)
				shouldServeChallenge = true
			}
		}

		if shouldServeChallenge {
			state.mu.Lock()
			if !state.challengeServed {
				state.challengeServed = true
				state.violationCount = 0
			} else {
				// Already served, this is a violation if it's not the verification (checked above)
				state.violationCount++
				if state.violationCount > m.cfg.MaxFailedChallenges {
					state.blocked = true
					state.blockedAt = time.Now()
					state.mu.Unlock()
					if m.cfg.PrometheusEnabled {
						metrics.DroppedRequests.WithLabelValues("challenge_violation").Inc()
					}
					if m.cfg.BlockAction == "close" {
						if hijacker, ok := w.(http.Hijacker); ok {
							conn, _, err := hijacker.Hijack()
							if err == nil {
								conn.Close()
							}
						}
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}
			state.mu.Unlock()

			m.serveChallenge(w, r, "")
			return
		}

		// Increment request counter
		m.rl.IncReq()
		if m.cfg.PrometheusEnabled {
			metrics.AllowedRequests.WithLabelValues("normal").Inc()
		}

		if m.cfg.AutoMitigationOnTimeout {
			start := time.Now()

			// Use a response writer wrapper to capture status code
			rr := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rr, r)

			duration := time.Since(start)

			// Consider it a timeout if it took longer than threshold OR returned a gateway timeout/bad gateway
			if duration >= m.cfg.TimeoutThreshold || rr.statusCode == http.StatusGatewayTimeout || rr.statusCode == http.StatusBadGateway {
				count := atomic.AddInt64(&m.timeoutCount, 1)
				if count >= int64(m.cfg.MaxTimeouts) {
					// We just crossed the threshold. The next requests will trigger mitigation immediately.
					newUntil := time.Now().Add(m.cfg.MitigationTime).Unix()
					atomic.StoreInt64(&m.mitigationUntil, newUntil)
				}
			}
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// responseRecorder captures the status code from the ResponseWriter
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// Hijack implements the http.Hijacker interface to support websockets and other hijacked connections
func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rr.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush implements the http.Flusher interface
func (rr *responseRecorder) Flush() {
	if flusher, ok := rr.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
