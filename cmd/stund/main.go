// Command stund runs a STUN server (RFC 8489 Binding over UDP, TCP, TLS,
// and DTLS, optional RFC 5780 NAT behavior discovery).
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pion/dtls/v3"

	"stun/internal/server"
)

// version is the build version, overridden at release time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("stund failed", "err", err)
		os.Exit(1)
	}
}

// run wires up the daemon and blocks until a serve loop returns or shutdown
// closes the sockets. All setup errors flow back here so main has the one
// exit point.
func run() error {
	o := parseFlags()
	if o.showVersion {
		fmt.Println(version)
		return nil
	}
	if err := o.apply(); err != nil {
		return err
	}

	d := &daemon{errc: make(chan error, 6)}
	if err := d.startBinding(o); err != nil {
		return err
	}
	if o.tcp {
		if err := d.startTCP(o.addr); err != nil {
			return err
		}
	}
	if o.tlsCert != "" {
		if err := d.startTLS(o); err != nil {
			return err
		}
	}
	if o.metricsAddr != "" {
		if err := d.startMetrics(o.metricsAddr); err != nil {
			return err
		}
	}

	d.awaitShutdown()

	// The first serve loop to return decides the exit code; a nil means a
	// socket was closed during shutdown.
	return <-d.errc
}

// options holds the parsed command-line flags.
type options struct {
	addr        string
	tcp         bool
	rps         float64
	altIP       string
	altPort     uint
	realm       string
	users       map[string]string
	tlsAddr     string
	tlsCert     string
	tlsKey      string
	alt         server.AlternateServer
	metricsAddr string
	verbose     bool
	showVersion bool
}

func parseFlags() *options {
	o := &options{users: map[string]string{}}
	flag.StringVar(&o.addr, "addr", ":3478", "listen address (UDP and TCP)")
	flag.BoolVar(&o.tcp, "tcp", true, "also serve STUN over TCP")
	flag.Float64Var(&o.rps, "rps", 10, "per-IP request rate limit (0 disables)")
	flag.StringVar(&o.altIP, "alt-ip", "", "second IP; enables RFC 5780 NAT discovery (requires explicit IP in -addr)")
	flag.UintVar(&o.altPort, "alt-port", 0, "alternate port for NAT discovery (default: primary port + 1)")
	flag.StringVar(&o.realm, "realm", "", "authentication realm (long-term credentials; needs -user)")
	flag.Func("user", "username:password credential, repeatable (needs -realm)", func(s string) error {
		u, p, ok := strings.Cut(s, ":")
		if !ok || u == "" {
			return errors.New("want username:password")
		}
		o.users[u] = p
		return nil
	})
	flag.StringVar(&o.tlsAddr, "tls-addr", ":5349", "TLS and DTLS listen address (active with -tls-cert)")
	flag.StringVar(&o.tlsCert, "tls-cert", "", "certificate file; with -tls-key, serves stuns over TLS and DTLS")
	flag.StringVar(&o.tlsKey, "tls-key", "", "private key file (needs -tls-cert)")
	flag.Func("redirect", "ip:port to send clients to via 300 Try Alternate; repeatable, one per address family", func(s string) error {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return err
		}
		if ap.Addr().Unmap().Is6() {
			o.alt.V6 = ap
		} else {
			o.alt.V4 = ap
		}
		return nil
	})
	flag.StringVar(&o.alt.Domain, "redirect-domain", "", "ALTERNATE-DOMAIN sent with redirects, for TLS/DTLS certificate validation")
	flag.StringVar(&o.metricsAddr, "metrics-addr", "", "HTTP listen address serving Prometheus counters on /metrics (empty disables)")
	flag.BoolVar(&o.verbose, "v", false, "enable debug logging")
	flag.BoolVar(&o.showVersion, "version", false, "print version and exit")
	flag.Parse()
	return o
}

// apply validates cross-flag constraints and installs the parsed options into
// the server package's globals.
func (o *options) apply() error {
	if o.verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	server.RPS, server.Burst = o.rps, 2*o.rps

	if (o.realm != "") != (len(o.users) > 0) {
		return errors.New("auth needs both -realm and -user")
	}
	if o.realm != "" {
		auth, err := server.NewAuth(o.realm, o.users)
		if err != nil {
			return fmt.Errorf("bad credentials: %w", err)
		}
		server.Credentials = auth
		slog.Info("long-term credential auth enabled", "realm", o.realm, "users", len(o.users))
	}

	if o.alt.Domain != "" && !o.alt.V4.IsValid() && !o.alt.V6.IsValid() {
		return errors.New("-redirect-domain needs at least one -redirect target")
	}
	if o.alt.V4.IsValid() || o.alt.V6.IsValid() {
		server.Alternate = &o.alt
		slog.Info("redirecting via 300 Try Alternate", "v4", o.alt.V4, "v6", o.alt.V6, "domain", o.alt.Domain)
	}

	if (o.tlsCert != "") != (o.tlsKey != "") {
		return errors.New("TLS needs both -tls-cert and -tls-key")
	}
	return nil
}

// daemon accumulates the running listeners: errc collects the first serve
// error, closers are shut in awaitShutdown.
type daemon struct {
	errc    chan error
	closers []io.Closer
}

// serve registers c for shutdown and runs its serve loop in the background.
func (d *daemon) serve(c io.Closer, loop func() error) {
	go func() { d.errc <- loop() }()
	d.closers = append(d.closers, c)
}

// startBinding opens the primary UDP socket, or the four NAT-discovery sockets
// when -alt-ip is set.
func (d *daemon) startBinding(o *options) error {
	if o.altIP != "" {
		disc, err := listenDiscovery(o.addr, o.altIP, uint16(o.altPort))
		if err != nil {
			return fmt.Errorf("nat discovery setup: %w", err)
		}
		d.serve(disc, disc.Serve)
		return nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", o.addr)
	if err != nil {
		return fmt.Errorf("bad -addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	slog.Info("listening", "udp", conn.LocalAddr())
	d.serve(conn, func() error { return server.Serve(conn) })
	return nil
}

func (d *daemon) startTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen: %w", err)
	}
	slog.Info("listening", "tcp", ln.Addr())
	d.serve(ln, func() error { return server.ServeTCP(ln) })
	return nil
}

// startTLS serves stuns over both TLS (STUN inside the TCP stream) and DTLS.
func (d *daemon) startTLS(o *options) error {
	// The loader re-reads the pair when the files change, so cert rotation
	// doesn't need a restart; both stacks ask it per handshake.
	loader, err := newCertLoader(o.tlsCert, o.tlsKey)
	if err != nil {
		return fmt.Errorf("bad certificate: %w", err)
	}
	// STUN over TLS is STUN over TCP inside the stream, so ServeTCP serves it;
	// MinVersion per RFC 8489 §6.2.3's cipher requirements.
	ln, err := tls.Listen("tcp", o.tlsAddr, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loader.get() },
		MinVersion:     tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("tls listen: %w", err)
	}
	slog.Info("listening", "tls", ln.Addr())
	d.serve(ln, func() error { return server.ServeTCP(ln) })

	udpAddr, err := net.ResolveUDPAddr("udp", o.tlsAddr)
	if err != nil {
		return fmt.Errorf("bad -tls-addr: %w", err)
	}
	dln, err := dtls.ListenWithOptions("udp", udpAddr,
		dtls.WithGetCertificate(func(*dtls.ClientHelloInfo) (*tls.Certificate, error) { return loader.get() }))
	if err != nil {
		return fmt.Errorf("dtls listen: %w", err)
	}
	slog.Info("listening", "dtls", dln.Addr())
	d.serve(dln, func() error { return server.ServeDTLS(dln) })
	return nil
}

func (d *daemon) startMetrics(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("metrics listen: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		server.WriteMetrics(w)
	})
	slog.Info("listening", "metrics", ln.Addr())
	go func() {
		if err := http.Serve(ln, mux); !errors.Is(err, net.ErrClosed) {
			d.errc <- err
		}
	}()
	d.closers = append(d.closers, ln)
	return nil
}

// awaitShutdown closes every listener on SIGINT/SIGTERM. Each serve loop then
// returns nil, unblocking run.
func (d *daemon) awaitShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("shutting down")
		for _, c := range d.closers {
			if err := c.Close(); err != nil {
				slog.Warn("close failed", "err", err)
			}
		}
	}()
}

// listenDiscovery parses the discovery flags and opens the four sockets:
// addr must be an explicit "ip:port" (the primary), altIPStr the second IP,
// and altPort defaults to the primary port + 1.
func listenDiscovery(addr, altIPStr string, altPort uint16) (*server.Discovery, error) {
	primary, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	altIP, err := netip.ParseAddr(altIPStr)
	if err != nil {
		return nil, err
	}
	if altPort == 0 {
		altPort = primary.Port() + 1
	}
	d, err := server.ListenDiscovery(primary.Addr(), altIP, primary.Port(), altPort)
	if err != nil {
		return nil, err
	}
	slog.Info("nat discovery listening",
		"ips", []netip.Addr{primary.Addr(), altIP},
		"ports", []uint16{primary.Port(), altPort})
	return d, nil
}
