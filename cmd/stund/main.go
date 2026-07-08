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
	addr := flag.String("addr", ":3478", "UDP listen address")
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
	slog.Info("listening", "addr", conn.LocalAddr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("shutting down")
		conn.Close()
	}()

	if err := server.Serve(conn); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
