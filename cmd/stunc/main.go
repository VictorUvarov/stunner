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

// version is the build version, overridden at release time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

// Process exit codes.
const (
	exitOK       = 0 // success; reflexive address printed
	exitFailure  = 1 // dial, transaction, or other runtime error
	exitUsage    = 2 // wrong arguments or bad flags
	exitRedirect = 3 // server answered 300 Try Alternate
)

func main() {
	proto := flag.String("proto", "udp", "transport: udp, tcp, tls, or dtls")
	user := flag.String("user", "", "username:password for servers that demand auth")
	software := flag.String("software", "stunc", "SOFTWARE attribute value (empty sends none)")
	insecure := flag.Bool("insecure", false, "skip certificate verification (tls/dtls; dev servers)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: stunc [flags] host[:port]\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		os.Exit(exitOK)
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(exitUsage)
	}

	cfg := stunclient.Config{Software: *software}
	if *user != "" {
		u, p, ok := strings.Cut(*user, ":")
		if !ok || u == "" {
			os.Exit(fail(errors.New("-user wants username:password")))
		}
		cfg.Username, cfg.Password = u, p
	}

	os.Exit(query(*proto, flag.Arg(0), *insecure, cfg))
}

// query dials, asks for the reflexive address, prints it, and returns the
// process exit code. It owns the connection, so its deferred Close runs on
// every path — unlike calling os.Exit here, which would skip it.
func query(proto, addr string, insecure bool, cfg stunclient.Config) int {
	c, err := dial(proto, addr, insecure, cfg)
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "stunc: close:", err)
		}
	}()

	ap, err := c.Binding()
	if err != nil {
		var r *stunclient.Redirect
		if errors.As(err, &r) {
			fmt.Fprintf(os.Stderr, "stunc: server redirects to %v", r.Alternate)
			if r.Domain != "" {
				fmt.Fprintf(os.Stderr, " (domain %s)", r.Domain)
			}
			fmt.Fprintln(os.Stderr)
			return exitRedirect
		}
		return fail(err)
	}
	fmt.Println(ap)
	return exitOK
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

// fail prints err to stderr and returns the exit code for it. Callers own the
// os.Exit so any pending defers still run.
func fail(err error) int {
	fmt.Fprintln(os.Stderr, "stunc:", err)
	return exitFailure
}
