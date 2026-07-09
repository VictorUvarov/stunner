// Command pion-interop sends a STUN Binding request to a running stund using
// pion/stun — a wholly independent Go implementation — and validates the
// XOR-MAPPED-ADDRESS it gets back. Sharing no code with our server, it catches
// the class of wire-format bug that a stunc-against-stund e2e never can.
//
// It lives in its own module so pion/stun stays out of the main go.mod.
//
//	go -C test/interop/pion run . 127.0.0.1:3478
package main

import (
	"fmt"
	"os"

	"github.com/pion/stun/v3"
)

func main() {
	addr := "127.0.0.1:3478"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	c, err := stun.Dial("udp", addr)
	if err != nil {
		fail("dial", err)
	}
	defer c.Close() //nolint:errcheck // best-effort on a throwaway client

	var (
		xorAddr stun.XORMappedAddress
		inner   error
	)
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if err := c.Do(req, func(res stun.Event) {
		if res.Error != nil {
			inner = res.Error
			return
		}
		inner = xorAddr.GetFrom(res.Message)
	}); err != nil {
		fail("binding", err)
	}
	if inner != nil {
		fail("response", inner)
	}

	fmt.Printf("pion interop OK: XOR-MAPPED-ADDRESS %s\n", xorAddr)
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "pion-interop: %s: %v\n", stage, err)
	os.Exit(1)
}
