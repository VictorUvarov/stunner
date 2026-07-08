// Command stund runs a STUN server (RFC 8489 Binding over UDP and TCP,
// optional RFC 5780 NAT behavior discovery).
package main

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"stun/server"
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
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Both serve loops exit nil when their socket is closed, so shutdown is
	// just closing the sockets; the first result decides the exit code.
	errc := make(chan error, 3)
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
