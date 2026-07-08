package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
)

// Counters is one transport's monotonic counters. All fields are updated
// atomically by the serve loops and may be read at any time.
type Counters struct {
	Received atomic.Uint64 // messages read off the wire, including non-STUN junk
	Replies  atomic.Uint64 // responses sent (successes and errors)
	Errors   atomic.Uint64 // error-class responses, a subset of Replies
	Limited  atomic.Uint64 // messages dropped by the per-IP rate limiter
}

// transports fixes the export order; every serve loop counts under one of
// these names. TCP and TLS are split because they answer on different
// listeners even though they share a serve loop.
var transports = []string{"udp", "tcp", "tls", "dtls", "discovery"}

// Metrics holds the per-transport counters. Silent discards (malformed
// input, bad fingerprints, indications) are the remainder
// Received − Replies − Limited; they get no counter of their own.
var Metrics = func() map[string]*Counters {
	m := make(map[string]*Counters, len(transports))
	for _, t := range transports {
		m[t] = &Counters{}
	}
	return m
}()

// countReply records one sent response, classifying it as an error by the
// class bits of the marshaled message type (RFC 8489 §5: 0b11 = error).
func (c *Counters) countReply(resp []byte) {
	c.Replies.Add(1)
	if binary.BigEndian.Uint16(resp[0:2])&0x0110 == 0x0110 {
		c.Errors.Add(1)
	}
}

// WriteMetrics renders every counter in the Prometheus text exposition
// format. Zero-valued series are included so scrapers see a stable set.
func WriteMetrics(w io.Writer) {
	series := []struct {
		name, help string
		value      func(*Counters) uint64
	}{
		{"stund_received_total", "Messages read off the wire, including non-STUN input.",
			func(c *Counters) uint64 { return c.Received.Load() }},
		{"stund_replies_total", "Responses sent, successes and errors.",
			func(c *Counters) uint64 { return c.Replies.Load() }},
		{"stund_errors_total", "Error responses sent, a subset of replies.",
			func(c *Counters) uint64 { return c.Errors.Load() }},
		{"stund_ratelimited_total", "Messages dropped by the per-IP rate limiter.",
			func(c *Counters) uint64 { return c.Limited.Load() }},
	}
	for _, s := range series {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", s.name, s.help, s.name)
		for _, t := range transports {
			fmt.Fprintf(w, "%s{transport=%q} %d\n", s.name, t, s.value(Metrics[t]))
		}
	}
}
