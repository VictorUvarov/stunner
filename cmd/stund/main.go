// Command stund runs a STUN server (RFC 8489 Binding over UDP, TCP, TLS,
// and DTLS, optional RFC 5780 NAT behavior discovery).
package main

import (
	"crypto/tls"
	"errors"
	"flag"
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

func main() {
	addr := flag.String("addr", ":3478", "listen address (UDP and TCP)")
	tcp := flag.Bool("tcp", true, "also serve STUN over TCP")
	rps := flag.Float64("rps", 10, "per-IP request rate limit (0 disables)")
	altIP := flag.String("alt-ip", "", "second IP; enables RFC 5780 NAT discovery (requires explicit IP in -addr)")
	altPort := flag.Uint("alt-port", 0, "alternate port for NAT discovery (default: primary port + 1)")
	realm := flag.String("realm", "", "authentication realm (long-term credentials; needs -user)")
	users := map[string]string{}
	flag.Func("user", "username:password credential, repeatable (needs -realm)", func(s string) error {
		u, p, ok := strings.Cut(s, ":")
		if !ok || u == "" {
			return errors.New("want username:password")
		}
		users[u] = p
		return nil
	})
	tlsAddr := flag.String("tls-addr", ":5349", "TLS and DTLS listen address (active with -tls-cert)")
	tlsCert := flag.String("tls-cert", "", "certificate file; with -tls-key, serves stuns over TLS and DTLS")
	tlsKey := flag.String("tls-key", "", "private key file (needs -tls-cert)")
	var alt server.AlternateServer
	flag.Func("redirect", "ip:port to send clients to via 300 Try Alternate; repeatable, one per address family", func(s string) error {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return err
		}
		if ap.Addr().Unmap().Is6() {
			alt.V6 = ap
		} else {
			alt.V4 = ap
		}
		return nil
	})
	flag.StringVar(&alt.Domain, "redirect-domain", "", "ALTERNATE-DOMAIN sent with redirects, for TLS/DTLS certificate validation")
	metricsAddr := flag.String("metrics-addr", "", "HTTP listen address serving Prometheus counters on /metrics (empty disables)")
	verbose := flag.Bool("v", false, "enable debug logging")
	flag.Parse()
	server.RPS, server.Burst = *rps, 2**rps
	if (*realm != "") != (len(users) > 0) {
		slog.Error("auth needs both -realm and -user")
		os.Exit(1)
	}
	if *realm != "" {
		auth, err := server.NewAuth(*realm, users)
		if err != nil {
			slog.Error("bad credentials", "err", err)
			os.Exit(1)
		}
		server.Credentials = auth
		slog.Info("long-term credential auth enabled", "realm", *realm, "users", len(users))
	}
	if alt.Domain != "" && !alt.V4.IsValid() && !alt.V6.IsValid() {
		slog.Error("-redirect-domain needs at least one -redirect target")
		os.Exit(1)
	}
	if alt.V4.IsValid() || alt.V6.IsValid() {
		server.Alternate = &alt
		slog.Info("redirecting via 300 Try Alternate", "v4", alt.V4, "v6", alt.V6, "domain", alt.Domain)
	}
	if (*tlsCert != "") != (*tlsKey != "") {
		slog.Error("TLS needs both -tls-cert and -tls-key")
		os.Exit(1)
	}
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// All serve loops exit nil when their socket is closed, so shutdown is
	// just closing the sockets; the first result decides the exit code.
	errc := make(chan error, 6)
	var closers []io.Closer

	if *altIP != "" {
		d, err := listenDiscovery(*addr, *altIP, uint16(*altPort))
		if err != nil {
			slog.Error("nat discovery setup failed", "err", err)
			os.Exit(1)
		}
		go func() { errc <- d.Serve() }()
		closers = append(closers, d)
	} else {
		udpAddr, err := net.ResolveUDPAddr("udp", *addr)
		if err != nil {
			slog.Error("bad -addr", "err", err)
			os.Exit(1)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			slog.Error("listen failed", "err", err)
			os.Exit(1)
		}
		slog.Info("listening", "udp", conn.LocalAddr())
		go func() { errc <- server.Serve(conn) }()
		closers = append(closers, conn)
	}

	if *tcp {
		ln, err := net.Listen("tcp", *addr)
		if err != nil {
			slog.Error("tcp listen failed", "err", err)
			os.Exit(1)
		}
		slog.Info("listening", "tcp", ln.Addr())
		go func() { errc <- server.ServeTCP(ln) }()
		closers = append(closers, ln)
	}

	if *tlsCert != "" {
		// The loader re-reads the pair when the files change, so cert
		// rotation doesn't need a restart; both stacks ask it per handshake.
		loader, err := newCertLoader(*tlsCert, *tlsKey)
		if err != nil {
			slog.Error("bad certificate", "err", err)
			os.Exit(1)
		}
		// STUN over TLS is STUN over TCP inside the stream, so ServeTCP
		// serves it; MinVersion per RFC 8489 §6.2.3's cipher requirements.
		ln, err := tls.Listen("tcp", *tlsAddr, &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loader.get() },
			MinVersion:     tls.VersionTLS12,
		})
		if err != nil {
			slog.Error("tls listen failed", "err", err)
			os.Exit(1)
		}
		slog.Info("listening", "tls", ln.Addr())
		go func() { errc <- server.ServeTCP(ln) }()
		closers = append(closers, ln)

		udpAddr, err := net.ResolveUDPAddr("udp", *tlsAddr)
		if err != nil {
			slog.Error("bad -tls-addr", "err", err)
			os.Exit(1)
		}
		dln, err := dtls.ListenWithOptions("udp", udpAddr,
			dtls.WithGetCertificate(func(*dtls.ClientHelloInfo) (*tls.Certificate, error) { return loader.get() }))
		if err != nil {
			slog.Error("dtls listen failed", "err", err)
			os.Exit(1)
		}
		slog.Info("listening", "dtls", dln.Addr())
		go func() { errc <- server.ServeDTLS(dln) }()
		closers = append(closers, dln)
	}

	if *metricsAddr != "" {
		ln, err := net.Listen("tcp", *metricsAddr)
		if err != nil {
			slog.Error("metrics listen failed", "err", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			server.WriteMetrics(w)
		})
		slog.Info("listening", "metrics", ln.Addr())
		go func() {
			if err := http.Serve(ln, mux); !errors.Is(err, net.ErrClosed) {
				errc <- err
			}
		}()
		closers = append(closers, ln)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("shutting down")
		for _, c := range closers {
			c.Close()
		}
	}()

	if err := <-errc; err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
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
