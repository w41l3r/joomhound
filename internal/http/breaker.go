package http

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is rejecting requests.
var ErrCircuitOpen = errors.New("circuit breaker open: target is failing or rate-limiting")

// BreakerState is the state of a CircuitBreaker.
type BreakerState int

const (
	// StateClosed lets every request through (normal operation).
	StateClosed BreakerState = iota
	// StateOpen rejects every request until the cooldown expires.
	StateOpen
	// StateHalfOpen lets a limited number of probe requests through.
	StateHalfOpen
)

func (s BreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// BreakerConfig configures a CircuitBreaker.
type BreakerConfig struct {
	// Enabled turns the breaker on. A zero-value config is disabled so that
	// callers that do not care keep the old fail-forever behaviour.
	Enabled bool
	// FailureThreshold is the number of consecutive failures that trips the
	// breaker from closed to open.
	FailureThreshold int
	// OpenTimeout is how long the breaker stays open before allowing probes.
	OpenTimeout time.Duration
	// HalfOpenProbes is the number of concurrent probe requests allowed while
	// half-open. Each must succeed to close the breaker again.
	HalfOpenProbes int
}

// DefaultBreakerConfig returns a configuration tuned for web scanning: a
// handful of consecutive failures (host down, WAF blackholing us, connection
// reset) trips the breaker so we stop hammering a dead target.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		Enabled:          true,
		FailureThreshold: 8,
		OpenTimeout:      15 * time.Second,
		HalfOpenProbes:   2,
	}
}

// CircuitBreaker prevents a scan from burning its whole wordlist against a
// target that has stopped answering (or that has started blocking us). It is
// safe for concurrent use.
type CircuitBreaker struct {
	cfg BreakerConfig

	mu           sync.Mutex
	state        BreakerState
	failures     int
	openedAt     time.Time
	probesInUse  int
	probesPassed int

	// tripped counts how many times the breaker has opened, for reporting.
	tripped int
}

// NewCircuitBreaker builds a breaker from cfg.
func NewCircuitBreaker(cfg BreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 8
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = 15 * time.Second
	}
	if cfg.HalfOpenProbes <= 0 {
		cfg.HalfOpenProbes = 2
	}
	return &CircuitBreaker{cfg: cfg, state: StateClosed}
}

// Allow reports whether a request may proceed. When it returns true the caller
// must eventually call Success or Failure exactly once.
func (cb *CircuitBreaker) Allow() error {
	if cb == nil || !cb.cfg.Enabled {
		return nil
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		if time.Since(cb.openedAt) < cb.cfg.OpenTimeout {
			return ErrCircuitOpen
		}
		// Cooldown elapsed: move to half-open and let this request probe.
		cb.state = StateHalfOpen
		cb.probesInUse = 1
		cb.probesPassed = 0
		return nil

	case StateHalfOpen:
		if cb.probesInUse >= cb.cfg.HalfOpenProbes {
			return ErrCircuitOpen
		}
		cb.probesInUse++
		return nil
	}
	return nil
}

// Success records a successful request.
func (cb *CircuitBreaker) Success() {
	if cb == nil || !cb.cfg.Enabled {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0

	if cb.state == StateHalfOpen {
		cb.probesPassed++
		if cb.probesInUse > 0 {
			cb.probesInUse--
		}
		if cb.probesPassed >= cb.cfg.HalfOpenProbes {
			cb.state = StateClosed
			cb.probesPassed = 0
			cb.probesInUse = 0
		}
	}
}

// Failure records a failed request (network error, 5xx, or 429).
func (cb *CircuitBreaker) Failure() {
	if cb == nil || !cb.cfg.Enabled {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		// A probe failed: go straight back to open.
		cb.state = StateOpen
		cb.openedAt = time.Now()
		cb.probesInUse = 0
		cb.probesPassed = 0
		cb.tripped++

	case StateClosed:
		cb.failures++
		if cb.failures >= cb.cfg.FailureThreshold {
			cb.state = StateOpen
			cb.openedAt = time.Now()
			cb.failures = 0
			cb.tripped++
		}
	}
}

// State returns the current breaker state.
func (cb *CircuitBreaker) State() BreakerState {
	if cb == nil {
		return StateClosed
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Tripped returns how many times the breaker has opened.
func (cb *CircuitBreaker) Tripped() int {
	if cb == nil {
		return 0
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.tripped
}
