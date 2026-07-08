// Command stunc is a STUN client (RFC 8489 Binding): it asks a server what
// address it sees and prints it — one line, suitable for scripts. It speaks
// every transport stund serves, so it doubles as an end-to-end self-test:
//
//	stunc stun.example.org                # UDP, port 3478
//	stunc -proto tcp stun.example.org
//	stunc -proto tls stun.example.org     # port 5349
//	stunc -proto dtls -insecure 127.0.0.1 # self-signed dev server
//	stunc -user alice:s3cret 127.0.0.1:3489
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pion/dtls/v3"

	"stun/internal/stunclient"
)

func main() {
	proto := flag.String("proto", "udp", "transport: udp, tcp, tls, or dtls")
	user := flag.String("user", "", "username:password for servers that demand auth")
	software := flag.String("software", "stunc", "SOFTWARE attribute value (empty sends none)")
	insecure := flag.Bool("insecure", false, "skip certificate verification (tls/dtls; dev servers)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: stunc [flags] host[:port]\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	cfg := stunclient.Config{Software: *software}
	if *user != "" {
		u, p, ok := strings.Cut(*user, ":")
		if !ok || u == "" {
			fail(errors.New("-user wants username:password"))
		}
		cfg.Username, cfg.Password = u, p
	}

	c, err := dial(*proto, flag.Arg(0), *insecure, cfg)
	if err != nil {
		fail(err)
	}
	defer c.Close()

	ap, err := c.Binding()
	if err != nil {
		var r *stunclient.Redirect
		if errors.As(err, &r) {
			fmt.Fprintf(os.Stderr, "stunc: server redirects to %v", r.Alternate)
			if r.Domain != "" {
				fmt.Fprintf(os.Stderr, " (domain %s)", r.Domain)
			}
			fmt.Fprintln(os.Stderr)
			os.Exit(3)
		}
		fail(err)
	}
	fmt.Println(ap)
}

// dial connects addr over the chosen transport, filling in the scheme's
// default port (3478 for stun, 5349 for stuns).
func dial(proto, addr string, insecure bool, cfg stunclient.Config) (*stunclient.Client, error) {
	secure := proto == "tls" || proto == "dtls"
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "3478"
		if secure {
			port = "5349"
		}
		addr = net.JoinHostPort(addr, port)
	}
	host, _, _ := net.SplitHostPort(addr)

	switch proto {
	case "udp":
		return stunclient.DialUDP(addr, cfg)
	case "tcp":
		return stunclient.DialTCP(addr, cfg)
	case "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			return nil, err
		}
		return stunclient.NewStream(conn, cfg), nil
	case "dtls":
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		conn, err := dtls.DialWithOptions("udp", raddr,
			dtls.WithServerName(host), dtls.WithInsecureSkipVerify(insecure))
		if err != nil {
			return nil, err
		}
		return stunclient.NewDatagram(conn, cfg), nil
	default:
		return nil, fmt.Errorf("unknown -proto %q (want udp, tcp, tls, or dtls)", proto)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "stunc:", err)
	os.Exit(1)
}
