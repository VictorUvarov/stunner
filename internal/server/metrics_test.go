package server

import (
	"strings"
	"testing"

	"stun/internal/stunmsg"
)

// snapshot copies a transport's counters so tests can assert deltas: the
// Metrics registry is package-global and other tests in the run also feed it.
func snapshot(name string) (received, replies, errors, limited uint64) {
	c := Metrics[name]
	return c.Received.Load(), c.Replies.Load(), c.Errors.Load(), c.Limited.Load()
}

func TestMetricsCountUDP(t *testing.T) {
	client := startServer(t)
	rcv0, rep0, err0, _ := snapshot("udp")

	// One success, one 420 error, one non-STUN datagram (received, no reply).
	roundTrip(t, client, newRequest(t).Marshal())
	bad := newRequest(t)
	bad.Add(0x7777, []byte{1, 2, 3, 4})
	resp := roundTrip(t, client, bad.Marshal())
	if errorCode(t, resp) != 420 {
		t.Fatalf("expected 420, got %v", resp)
	}
	if _, err := client.Write([]byte("not stun")); err != nil {
		t.Fatal(err)
	}
	// The junk datagram draws no reply; the next exchange both flushes it
	// (UDP is ordered on loopback) and adds one more success.
	roundTrip(t, client, newRequest(t).Marshal())

	rcv1, rep1, err1, _ := snapshot("udp")
	if got := rcv1 - rcv0; got != 4 {
		t.Errorf("received delta = %d, want 4", got)
	}
	if got := rep1 - rep0; got != 3 {
		t.Errorf("replies delta = %d, want 3", got)
	}
	if got := err1 - err0; got != 1 {
		t.Errorf("errors delta = %d, want 1", got)
	}
}

func TestWriteMetrics(t *testing.T) {
	var b strings.Builder
	WriteMetrics(&b)
	out := b.String()
	for _, want := range []string{
		"# TYPE stund_received_total counter",
		`stund_received_total{transport="udp"}`,
		`stund_replies_total{transport="dtls"}`,
		`stund_errors_total{transport="tls"}`,
		`stund_ratelimited_total{transport="discovery"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q:\n%s", want, out)
		}
	}
}

// Guard the class-bit test countReply relies on: an error response really
// has both class bits set once marshaled.
func TestCountReplyClassifiesErrors(t *testing.T) {
	var c Counters
	errResp := &stunmsg.Message{Type: stunmsg.BindingError}
	errResp.AddErrorCode(400, "Bad Request")
	c.countReply(errResp.Marshal())
	c.countReply((&stunmsg.Message{Type: stunmsg.BindingSuccess}).Marshal())
	if c.Replies.Load() != 2 || c.Errors.Load() != 1 {
		t.Fatalf("replies=%d errors=%d, want 2/1", c.Replies.Load(), c.Errors.Load())
	}
}
