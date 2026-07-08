// Command stund runs a STUN server (RFC 8489, Binding over UDP).
package main

import (
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"stun/server"
)

func main() {
	addr := flag.String("addr", ":3478", "listen address (UDP and TCP)")
	tcp := flag.Bool("tcp", true, "also serve STUN over TCP")
	rps := flag.Float64("rps", 10, "per-IP request rate limit (0 disables)")
	verbose := flag.Bool("v", false, "enable debug logging")
	flag.Parse()
	server.RPS, server.Burst = *rps, 2**rps
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

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

	// Both serve loops exit nil when their socket is closed, so shutdown is
	// just closing the sockets; the first result decides the exit code.
	errc := make(chan error, 2)
	go func() { errc <- server.Serve(conn) }()

	var ln net.Listener
	if *tcp {
		ln, err = net.Listen("tcp", *addr)
		if err != nil {
			slog.Error("tcp listen failed", "err", err)
			os.Exit(1)
		}
		slog.Info("listening", "tcp", ln.Addr())
		go func() { errc <- server.ServeTCP(ln) }()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("shutting down")
		conn.Close()
		if ln != nil {
			ln.Close()
		}
	}()

	if err := <-errc; err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
