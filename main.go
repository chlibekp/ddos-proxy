package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds the application configuration.
type Config struct {
	BackendURL         string
	Port               string
	MaxReqPerSec       int64
	MaxConnPerSec      int64
	JWTSecret          []byte
	VerifyTime         time.Duration
	MitigationTime     time.Duration
	TurnstileSiteKey   string
	TurnstileSecretKey string
	AlwaysOn           bool
	UseForwardedFor    bool
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	backendURL := os.Getenv("PROXY_BACKEND_URL")
	if backendURL == "" {
		return nil, os.ErrNotExist
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	maxReq := int64(300)
	if s := os.Getenv("PROXY_MAX_REQ"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			maxReq = v
		}
	}

	maxConn := int64(50)
	if s := os.Getenv("PROXY_MAX_CONN"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			maxConn = v
		}
	}

	jwtSecret := os.Getenv("PROXY_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default-insecure-secret-please-change"
	}

	verifyTime := 10 * time.Minute // Default 10 minutes
	if s := os.Getenv("PROXY_VERIFY_TIME"); s != "" {
		if v, err := time.ParseDuration(s); err == nil {
			verifyTime = v
		} else if vInt, err := strconv.Atoi(s); err == nil {
			verifyTime = time.Duration(vInt) * time.Second
		}
	}

	mitigationTime := 5 * time.Minute // Default 5 minutes
	if s := os.Getenv("PROXY_MITIGATION_TIME"); s != "" {
		if v, err := time.ParseDuration(s); err == nil {
			mitigationTime = v
		} else if vInt, err := strconv.Atoi(s); err == nil {
			mitigationTime = time.Duration(vInt) * time.Second
		}
	}

	alwaysOn := false
	if s := os.Getenv("PROXY_ALWAYS_ON"); s == "true" || s == "1" {
		alwaysOn = true
	}

	useForwardedFor := false
	if s := os.Getenv("PROXY_USE_FORWARDED_FOR"); s == "true" || s == "1" {
		useForwardedFor = true
	}

	return &Config{
		BackendURL:         backendURL,
		Port:               port,
		MaxReqPerSec:       maxReq,
		MaxConnPerSec:      maxConn,
		JWTSecret:          []byte(jwtSecret),
		VerifyTime:         verifyTime,
		MitigationTime:     mitigationTime,
		TurnstileSiteKey:   os.Getenv("PROXY_TURNSTILE_PUBLIC_KEY"),
		TurnstileSecretKey: os.Getenv("PROXY_TURNSTILE_PRIVATE_KEY"),
		AlwaysOn:           alwaysOn,
		UseForwardedFor:    useForwardedFor,
	}, nil
}

// RateLimiter tracks global request and connection rates.
type RateLimiter struct {
	reqCount  int64
	connCount int64
}

func (rl *RateLimiter) Reset() {
	atomic.StoreInt64(&rl.reqCount, 0)
	atomic.StoreInt64(&rl.connCount, 0)
}

func (rl *RateLimiter) IncReq() {
	atomic.AddInt64(&rl.reqCount, 1)
}

func (rl *RateLimiter) IncConn() {
	atomic.AddInt64(&rl.connCount, 1)
}

func (rl *RateLimiter) GetCounts() (int64, int64) {
	return atomic.LoadInt64(&rl.reqCount), atomic.LoadInt64(&rl.connCount)
}

// ClientState tracks the state of a single client IP.
type ClientState struct {
	mu              sync.Mutex
	blocked         bool
	blockedAt       time.Time
	violationCount  int
	challengeServed bool
	lastSeen        time.Time
}

// App holds the application state.
type App struct {
	cfg             *Config
	rl              *RateLimiter
	templates       *template.Template
	mitigationUntil int64    // Atomic unix timestamp
	ipStates        sync.Map // map[string]*ClientState
}

// ChallengeData is passed to the template.
type ChallengeData struct {
	Error       string
	SiteKey     string
	OriginalURL string
}

// NewProxy creates a new reverse proxy handler for the given target URL.
func NewProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		originalDirector(req)
		req.Host = originalHost
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("Proxy error", "error", err, "path", r.URL.Path)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return proxy
}

func (app *App) getClientIP(r *http.Request) string {
	if app.cfg.UseForwardedFor {
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

func (app *App) verifyTurnstile(responseToken, remoteIP string) bool {
	formData := url.Values{}
	formData.Set("secret", app.cfg.TurnstileSecretKey)
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

func (app *App) serveChallenge(w http.ResponseWriter, r *http.Request, errMsg string) {
	data := ChallengeData{
		Error:       errMsg,
		SiteKey:     app.cfg.TurnstileSiteKey,
		OriginalURL: r.URL.String(),
	}

	w.WriteHeader(http.StatusOK)
	app.templates.Execute(w, data)
}

func (app *App) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		app.serveChallenge(w, r, "Invalid form data")
		return
	}

	// Turnstile Verification
	responseToken := r.FormValue("cf-turnstile-response")
	if responseToken == "" {
		app.serveChallenge(w, r, "Please complete the CAPTCHA")
		return
	}
	ip := app.getClientIP(r)
	if !app.verifyTurnstile(responseToken, ip) {
		app.serveChallenge(w, r, "CAPTCHA verification failed")
		return
	}

	// Generate JWT
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"authorized": true,
		"exp":        time.Now().Add(app.cfg.VerifyTime).Unix(),
	})

	tokenString, err := jwtToken.SignedString(app.cfg.JWTSecret)
	if err != nil {
		slog.Error("Failed to sign JWT", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "proxy_auth",
		Value:    tokenString,
		Expires:  time.Now().Add(app.cfg.VerifyTime),
		HttpOnly: true,
		Path:     "/",
	})

	// Reset IP state upon successful verification
	if val, ok := app.ipStates.Load(ip); ok {
		state := val.(*ClientState)
		state.mu.Lock()
		state.violationCount = 0
		state.challengeServed = false
		state.blocked = false
		state.mu.Unlock()
	}

	// Redirect to original URL
	originalURL := r.FormValue("original_url")
	if originalURL == "" {
		originalURL = "/"
	}
	http.Redirect(w, r, originalURL, http.StatusFound)
}

func (app *App) getClientState(ip string) *ClientState {
	val, ok := app.ipStates.Load(ip)
	if ok {
		return val.(*ClientState)
	}
	state := &ClientState{
		lastSeen: time.Now(),
	}
	actual, loaded := app.ipStates.LoadOrStore(ip, state)
	if loaded {
		return actual.(*ClientState)
	}
	return state
}

func (app *App) cleanup() {
	now := time.Now()
	mitigationEnd := time.Unix(atomic.LoadInt64(&app.mitigationUntil), 0)
	attackEnded := now.After(mitigationEnd)

	// If attack has ended and we are not in always-on mode, we can be more aggressive with cleanup
	// But we still need to iterate to check blocked IPs expiration

	app.ipStates.Range(func(key, value interface{}) bool {
		state := value.(*ClientState)
		state.mu.Lock()
		defer state.mu.Unlock()

		// If attack ended and not always on, remove everything?
		// "reset states when the attack ends"
		if attackEnded && !app.cfg.AlwaysOn {
			app.ipStates.Delete(key)
			return true
		}

		// Unblock if blocked for more than 5 minutes
		if state.blocked && now.Sub(state.blockedAt) > 5*time.Minute {
			state.blocked = false
			state.violationCount = 0
			state.challengeServed = false
		}

		// Cleanup idle connections (e.g. 10 min inactivity)
		if now.Sub(state.lastSeen) > 10*time.Minute {
			app.ipStates.Delete(key)
		}

		return true
	})
}

func (app *App) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := app.getClientIP(r)

		// Check if IP is blocked
		state := app.getClientState(ip)
		state.mu.Lock()
		state.lastSeen = time.Now()
		if state.blocked {
			state.mu.Unlock()
			// Hijack and close connection
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					conn.Close()
				}
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
			return
		}
		state.mu.Unlock()

		// Bypass for challenge verification
		if r.URL.Path == "/challenge/verify" {
			app.verifyChallenge(w, r)
			return
		}

		// Check for valid JWT
		cookie, err := r.Cookie("proxy_auth")
		if err == nil {
			token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return app.cfg.JWTSecret, nil
			})

			if err == nil && token.Valid {
				// Valid token, pass through
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check global rate limits
		reqRate, connRate := app.rl.GetCounts()
		now := time.Now().Unix()
		mitigationUntil := atomic.LoadInt64(&app.mitigationUntil)

		// Determine if we should serve challenge
		shouldServeChallenge := app.cfg.AlwaysOn

		// If limits exceeded, extend mitigation time and enable challenge
		if reqRate >= app.cfg.MaxReqPerSec || connRate >= app.cfg.MaxConnPerSec {
			newUntil := time.Now().Add(app.cfg.MitigationTime).Unix()
			atomic.StoreInt64(&app.mitigationUntil, newUntil)
			shouldServeChallenge = true
		} else if now < mitigationUntil {
			shouldServeChallenge = true
		}

		if shouldServeChallenge {
			state.mu.Lock()
			if !state.challengeServed {
				state.challengeServed = true
				state.violationCount = 0
			} else {
				// Already served, this is a violation if it's not the verification (checked above)
				state.violationCount++
				if state.violationCount > 5 {
					state.blocked = true
					state.blockedAt = time.Now()
					state.mu.Unlock()
					if hijacker, ok := w.(http.Hijacker); ok {
						conn, _, err := hijacker.Hijack()
						if err == nil {
							conn.Close()
						}
					}
					return
				}
			}
			state.mu.Unlock()

			app.serveChallenge(w, r, "")
			return
		}

		// Increment request counter
		app.rl.IncReq()
		next.ServeHTTP(w, r)
	})
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := LoadConfig()
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

	rl := &RateLimiter{}
	app := &App{
		cfg:       cfg,
		rl:        rl,
		templates: tmpl,
	}

	// Start rate limiter reset ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.Reset()
		}
	}()

	// Start cleanup ticker
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			app.cleanup()
		}
	}()

	proxy := NewProxy(targetURL)
	handler := app.Middleware(proxy)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
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
