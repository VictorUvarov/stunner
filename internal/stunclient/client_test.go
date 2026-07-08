package stunclient

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"stun/internal/server"
	"stun/internal/stunmsg"
)

// fastCfg keeps retransmission tests snappy without changing the schedule's
// shape: 20ms initial RTO, 3 sends, 4×RTO final wait.
var fastCfg = Config{RTO: 20 * time.Millisecond, Rc: 3, Rm: 4}

// startUDP runs the real server on loopback and returns its address.
func startUDP(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(conn) }()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().String()
}

func TestBindingUDP(t *testing.T) {
	c, err := DialUDP(startUDP(t), Config{Software: "stunclient test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := c.Binding()
	if err != nil {
		t.Fatal(err)
	}
	want := c.conn.LocalAddr().(*net.UDPAddr).AddrPort()
	if got != want {
		t.Fatalf("mapped = %v, want %v", got, want)
	}
}

func TestBindingTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); server.ServeTCP(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })

	c, err := DialTCP(ln.Addr().String(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := c.Binding()
	if err != nil {
		t.Fatal(err)
	}
	want := c.conn.LocalAddr().(*net.TCPAddr).AddrPort()
	if got != want {
		t.Fatalf("mapped = %v, want %v", got, want)
	}
}

// TestRetransmission drops the first request on the floor; the client's
// §6.2.1 schedule must carry the transaction anyway.
func TestRetransmission(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		buf := make([]byte, 1500)
		for seen := 0; ; seen++ {
			n, src, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if seen == 0 {
				continue // swallow the first transmission
			}
			req, err := stunmsg.Parse(buf[:n])
			if err != nil {
				continue
			}
			resp := &stunmsg.Message{Type: stunmsg.BindingSuccess, TransactionID: req.TransactionID}
			resp.AddXORMappedAddress(src)
			resp.AddFingerprint()
			srv.WriteToUDPAddrPort(resp.Marshal(), src)
		}
	}()

	c, err := DialUDP(srv.LocalAddr().String(), fastCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Binding(); err != nil {
		t.Fatalf("transaction should have survived one dropped request: %v", err)
	}
}

// TestTimeout: a server that never answers must produce ErrTimeout after
// the full schedule, not hang.
func TestTimeout(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	c, err := DialUDP(srv.LocalAddr().String(), fastCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Binding(); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if want := fastCfg.total(); time.Since(start) < want {
		t.Fatalf("gave up after %v, schedule lasts %v", time.Since(start), want)
	}
}

// TestAuth runs the full RFC 8489 §9.2 handshake against the real server:
// 401 challenge, negotiated SHA-256 retry, integrity-checked response.
func TestAuth(t *testing.T) {
	auth, err := server.NewAuth("example.org", map[string]string{"alice": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	server.Credentials = auth
	addr := startUDP(t)
	t.Cleanup(func() { server.Credentials = nil })

	t.Run("good credentials", func(t *testing.T) {
		c, err := DialUDP(addr, Config{Username: "alice", Password: "s3cret"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Binding(); err != nil {
			t.Fatalf("authenticated binding failed: %v", err)
		}
		if !c.negotiated || c.chosen != stunmsg.PasswordAlgorithmSHA256 {
			t.Fatal("client did not negotiate the SHA-256 password algorithm")
		}
	})

	t.Run("bad password", func(t *testing.T) {
		c, err := DialUDP(addr, Config{Username: "alice", Password: "wrong"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		var er *ErrorResponse
		if _, err := c.Binding(); !errors.As(err, &er) || er.Code != 401 {
			t.Fatalf("err = %v, want 401 ErrorResponse", err)
		}
	})

	t.Run("no credentials configured", func(t *testing.T) {
		c, err := DialUDP(addr, Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		var er *ErrorResponse
		if _, err := c.Binding(); !errors.As(err, &er) || er.Code != 401 {
			t.Fatalf("err = %v, want 401 ErrorResponse", err)
		}
	})
}

// TestRedirect surfaces a 300 Try Alternate as a typed Redirect error.
func TestRedirect(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.7:3478")
	server.Alternate = &server.AlternateServer{V4: target, Domain: "stun.example.org"}
	addr := startUDP(t)
	t.Cleanup(func() { server.Alternate = nil })

	c, err := DialUDP(addr, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var r *Redirect
	if _, err := c.Binding(); !errors.As(err, &r) {
		t.Fatalf("err = %v, want Redirect", err)
	}
	if r.Alternate != target || r.Domain != "stun.example.org" {
		t.Fatalf("redirect = %+v", r)
	}
}
