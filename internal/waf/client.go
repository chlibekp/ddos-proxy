package waf

import (
	"sync"
	"time"
)

// ClientState tracks the state of a single client IP.
type ClientState struct {
	mu              sync.Mutex
	blocked         bool
	blockedAt       time.Time
	violationCount    int
	challengeServed   bool
	challengeServedAt time.Time
	lastSeen          time.Time
	verified        bool
	verifiedAt      time.Time
	powSalt         string
	errorCount      int
	l4Blocked       bool
}
