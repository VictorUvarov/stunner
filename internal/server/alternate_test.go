package server

import (
	"net/netip"
	"testing"

	"stun/internal/stunmsg"
)

// setAlternate installs a redirect target for the duration of the test.
// Like the Credentials tests: registered before startServer, the cleanup
// runs after the serve goroutine is joined, so the var is never rewritten
// under a live server.
func setAlternate(t *testing.T, alt *AlternateServer) {
	t.Helper()
	Alternate = alt
	t.Cleanup(func() { Alternate = nil })
}

func TestRedirect(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.1:3478")
	setAlternate(t, &AlternateServer{V4: target, Domain: "stun.example.org"})
	client := startServer(t)

	resp := roundTrip(t, client, newRequest(t).Marshal())
	if code := errorCode(t, resp); code != 300 {
		t.Fatalf("error code = %d, want 300", code)
	}
	got, err := resp.Address(stunmsg.AttrAlternateServer)
	if err != nil || got != target {
		t.Fatalf("ALTERNATE-SERVER = %v (%v), want %v", got, err, target)
	}
	if d, _ := resp.Get(stunmsg.AttrAlternateDomain); string(d) != "stun.example.org" {
		t.Fatalf("ALTERNATE-DOMAIN = %q", d)
	}
}

// §10: the ALTERNATE-SERVER address must match the source's family; with
// no target for it, the request is served normally.
func TestRedirectFamilyMissServes(t *testing.T) {
	setAlternate(t, &AlternateServer{V6: netip.MustParseAddrPort("[2001:db8::1]:3478")})
	client := startServer(t) // loopback IPv4 client

	if resp := roundTrip(t, client, newRequest(t).Marshal()); resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v, want success", resp)
	}
}

// With auth enabled the redirect happens only after credentials verify, and
// the 300 is integrity-protected so it can't be forged off-path.
func TestRedirectAuthenticatedIsSigned(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.1:3478")
	setAlternate(t, &AlternateServer{V4: target})
	client := startAuthServer(t)

	realm, nonce := challenge(t, client) // unauthenticated still draws the 401 first
	raw := roundTripRaw(t, client, legacyRequest(t, realm, nonce, testUser, testPass, false))
	resp, err := stunmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if code := errorCode(t, resp); code != 300 {
		t.Fatalf("error code = %d, want 300", code)
	}
	if got, err := resp.Address(stunmsg.AttrAlternateServer); err != nil || got != target {
		t.Fatalf("ALTERNATE-SERVER = %v (%v)", got, err)
	}
	if !stunmsg.VerifyMessageIntegrity(raw, stunmsg.LongTermKey(testUser, testRealm, testPass)) {
		t.Fatal("300 must carry valid MESSAGE-INTEGRITY for authenticated clients")
	}
}

// §10: after the mandatory same-family ALTERNATE-SERVER, the other
// family's target SHOULD follow when configured.
func TestRedirectListsOtherFamily(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.1:3478")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:3478")
	setAlternate(t, &AlternateServer{V4: v4, V6: v6})
	client := startServer(t) // IPv4 client: v4 is mandatory, v6 trails

	resp := roundTrip(t, client, newRequest(t).Marshal())
	var got []netip.AddrPort
	for _, a := range resp.Attrs {
		if a.Type == stunmsg.AttrAlternateServer {
			m := &stunmsg.Message{Attrs: []stunmsg.Attr{a}}
			ap, err := m.Address(stunmsg.AttrAlternateServer)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, ap)
		}
	}
	if len(got) != 2 || got[0] != v4 || got[1] != v6 {
		t.Fatalf("ALTERNATE-SERVER list = %v, want [%v %v]", got, v4, v6)
	}
}
