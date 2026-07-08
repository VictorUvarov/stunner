package server

import (
	"net/netip"
	"sync"
	"time"
)

// Rate-limit knobs, applied per source IP; each serve loop snapshots them
// when it starts. RPS is the sustained budget, Burst the extra headroom a
// quiet client accumulates. RPS <= 0 disables limiting.
var (
	RPS   = 10.0
	Burst = 20.0
)

// limiter is a token-bucket rate limiter keyed by source IP.
// ponytail: one mutex and one map for all IPs; shard the lock if it ever
// shows up in a profile.
type limiter struct {
	mu      sync.Mutex
	rps     float64
	burst   float64
	buckets map[netip.Addr]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rps, burst float64) *limiter {
	return &limiter{
		rps:     rps,
		burst:   burst,
		buckets: make(map[netip.Addr]*bucket),
		lastGC:  time.Now(),
	}
}

// allow reports whether a request from ip at time now fits its budget,
// spending one token if so. A nil limiter allows everything.
func (l *limiter) allow(ip netip.Addr, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gc(now)
	b := l.buckets[ip]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rps)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops buckets idle long enough to have refilled completely (they act
// identically to a fresh one). Runs at most once per minute, under l.mu.
func (l *limiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	idle := time.Duration(l.burst / l.rps * float64(time.Second))
	for ip, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, ip)
		}
	}
}
