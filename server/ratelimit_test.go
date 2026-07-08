package server

import (
	"net/netip"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := newLimiter(10, 3)
	ip := netip.MustParseAddr("192.0.2.7")
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !l.allow(ip, now) {
			t.Fatalf("request %d within burst denied", i)
		}
	}
	if l.allow(ip, now) {
		t.Fatal("request over burst allowed")
	}
	// 100ms at 10 rps refills exactly one token.
	if !l.allow(ip, now.Add(100*time.Millisecond)) {
		t.Fatal("refilled token denied")
	}
	// Other IPs have their own bucket.
	if !l.allow(netip.MustParseAddr("192.0.2.8"), now) {
		t.Fatal("separate IP throttled")
	}
	// Nil limiter allows everything.
	var nilLim *limiter
	if !nilLim.allow(ip, now) {
		t.Fatal("nil limiter denied")
	}
}

func TestLimiterGC(t *testing.T) {
	l := newLimiter(10, 20)
	now := time.Now()
	l.allow(netip.MustParseAddr("192.0.2.7"), now)
	// After >1min idle (and > full-refill time), the bucket is collected.
	l.allow(netip.MustParseAddr("192.0.2.8"), now.Add(2*time.Minute))
	if len(l.buckets) != 1 {
		t.Fatalf("buckets = %d, want 1 after gc", len(l.buckets))
	}
}

func TestServeRateLimits(t *testing.T) {
	oldRPS, oldBurst := RPS, Burst
	RPS, Burst = 5, 5
	defer func() { RPS, Burst = oldRPS, oldBurst }()

	client := startServer(t)
	const sent = 20
	for i := 0; i < sent; i++ {
		req := newRequest(t)
		if _, err := client.Write(req.Marshal()); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	buf := make([]byte, 1500)
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		if _, err := client.Read(buf); err != nil {
			break // timeout: no more replies
		}
		got++
	}
	// Burst of 5 plus at most a few refilled during the run.
	if got < 5 || got > 8 {
		t.Fatalf("got %d replies to %d requests, want ~5", got, sent)
	}
}
