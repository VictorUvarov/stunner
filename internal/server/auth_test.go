package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"stun/internal/stunmsg"
)

const (
	testRealm = "example.org"
	testUser  = "alice"
	testPass  = "s3cret"
)

// startAuthServer is startServer with long-term credentials enabled for the
// duration of the test.
func startAuthServer(t *testing.T) *net.UDPConn {
	t.Helper()
	auth, err := NewAuth(testRealm, map[string]string{testUser: testPass})
	if err != nil {
		t.Fatal(err)
	}
	Credentials = auth
	t.Cleanup(func() { Credentials = nil })
	return startServer(t)
}

// roundTripRaw is roundTrip but returns the raw response bytes, which
// integrity verification needs.
func roundTripRaw(t *testing.T, client *net.UDPConn, pkt []byte) []byte {
	t.Helper()
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// challenge sends an unauthenticated request and returns the realm and
// nonce from the resulting 401.
func challenge(t *testing.T, client *net.UDPConn) (realm, nonce []byte) {
	t.Helper()
	resp := roundTrip(t, client, newRequest(t).Marshal())
	if code := errorCode(t, resp); code != 401 {
		t.Fatalf("challenge error code = %d, want 401", code)
	}
	realm, _ = resp.Get(stunmsg.AttrRealm)
	nonce, ok := resp.Get(stunmsg.AttrNonce)
	if len(realm) == 0 || !ok {
		t.Fatalf("401 missing REALM/NONCE: %v", resp)
	}
	if algs, err := resp.PasswordAlgorithms(); err != nil || len(algs) == 0 {
		t.Fatalf("401 missing PASSWORD-ALGORITHMS: %v, %v", algs, err)
	}
	return realm, nonce
}

// legacyRequest builds an RFC 5389-style authenticated request: USERNAME +
// MD5 key, no password-algorithm attributes, signed with the given variant.
func legacyRequest(t *testing.T, realm, nonce []byte, user, pass string, sha2 bool) []byte {
	t.Helper()
	req := newRequest(t)
	req.Add(stunmsg.AttrUsername, []byte(user))
	req.Add(stunmsg.AttrRealm, realm)
	req.Add(stunmsg.AttrNonce, nonce)
	key := stunmsg.LongTermKey(user, string(realm), pass)
	if sha2 {
		req.AddMessageIntegritySHA256(key)
	} else {
		req.AddMessageIntegrity(key)
	}
	req.AddFingerprint()
	return req.Marshal()
}

// negotiatedRequest builds an RFC 8489 request: echoes PASSWORD-ALGORITHMS,
// selects SHA-256, uses USERHASH when anon is set, signs with
// MESSAGE-INTEGRITY-SHA256 keyed by the SHA-256 derivation.
func negotiatedRequest(t *testing.T, realm, nonce []byte, user, pass string, anon bool) []byte {
	t.Helper()
	req := newRequest(t)
	if anon {
		req.Add(stunmsg.AttrUserhash, stunmsg.Userhash(user, string(realm)))
	} else {
		req.Add(stunmsg.AttrUsername, []byte(user))
	}
	req.Add(stunmsg.AttrRealm, realm)
	req.Add(stunmsg.AttrNonce, nonce)
	req.AddPasswordAlgorithms([]uint16{stunmsg.PasswordAlgorithmSHA256, stunmsg.PasswordAlgorithmMD5})
	req.AddPasswordAlgorithm(stunmsg.PasswordAlgorithmSHA256)
	req.AddMessageIntegritySHA256(stunmsg.LongTermKeySHA256(user, string(realm), pass))
	req.AddFingerprint()
	return req.Marshal()
}

func errorCode(t *testing.T, resp *stunmsg.Message) int {
	t.Helper()
	if resp.Type != stunmsg.BindingError {
		t.Fatalf("type = %v, want error response", resp)
	}
	ec, ok := resp.Get(stunmsg.AttrErrorCode)
	if !ok || len(ec) < 4 {
		t.Fatalf("no ERROR-CODE in %v", resp)
	}
	return int(ec[2])*100 + int(ec[3])
}

func wantSuccess(t *testing.T, raw []byte) *stunmsg.Message {
	t.Helper()
	resp, err := stunmsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v, want success", resp)
	}
	if _, err := resp.XORMappedAddress(); err != nil {
		t.Fatal(err)
	}
	return resp
}

// Legacy clients (no password-algorithm attributes, MD5 key) must still
// authenticate, and per §9.2.4 the response then carries legacy
// MESSAGE-INTEGRITY — even when the request used the SHA-256 variant.
func TestAuthLegacyHandshake(t *testing.T) {
	// Subtests, not a plain loop: each startAuthServer writes Credentials,
	// and only a subtest boundary runs the cleanup that stops the previous
	// server before the next write.
	for _, sha2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("sha2=%v", sha2), func(t *testing.T) {
			client := startAuthServer(t)
			realm, nonce := challenge(t, client)
			if string(realm) != testRealm {
				t.Fatalf("realm = %q", realm)
			}
			raw := roundTripRaw(t, client, legacyRequest(t, realm, nonce, testUser, testPass, sha2))
			wantSuccess(t, raw)
			if !stunmsg.VerifyMessageIntegrity(raw, stunmsg.LongTermKey(testUser, testRealm, testPass)) {
				t.Fatal("response must carry legacy MESSAGE-INTEGRITY")
			}
		})
	}
}

// The full RFC 8489 flow: PASSWORD-ALGORITHMS echo, SHA-256 key, USERHASH
// anonymity; the response must be signed with MESSAGE-INTEGRITY-SHA256.
func TestAuthNegotiatedHandshake(t *testing.T) {
	for _, anon := range []bool{false, true} {
		t.Run(fmt.Sprintf("anon=%v", anon), func(t *testing.T) {
			client := startAuthServer(t)
			realm, nonce := challenge(t, client)
			raw := roundTripRaw(t, client, negotiatedRequest(t, realm, nonce, testUser, testPass, anon))
			wantSuccess(t, raw)
			if !stunmsg.VerifyMessageIntegritySHA256(raw, stunmsg.LongTermKeySHA256(testUser, testRealm, testPass)) {
				t.Fatal("response MESSAGE-INTEGRITY-SHA256 did not verify")
			}
		})
	}
}

func TestAuthWrongCredentials(t *testing.T) {
	client := startAuthServer(t)
	realm, nonce := challenge(t, client)
	for name, pkt := range map[string][]byte{
		"wrong password":   legacyRequest(t, realm, nonce, testUser, "wrong", false),
		"unknown user":     legacyRequest(t, realm, nonce, "mallory", testPass, false),
		"unknown userhash": negotiatedRequest(t, realm, nonce, "mallory", testPass, true),
	} {
		resp := roundTrip(t, client, pkt)
		if code := errorCode(t, resp); code != 401 {
			t.Fatalf("%s: error code = %d, want 401", name, code)
		}
	}
}

// §9.2.4: with the feature bit set in the echoed nonce, sending
// PASSWORD-ALGORITHM requires a matching PASSWORD-ALGORITHMS echo.
func TestAuthNegotiationViolationsAre400(t *testing.T) {
	client := startAuthServer(t)
	realm, nonce := challenge(t, client)

	build := func(mutate func(*stunmsg.Message)) []byte {
		req := newRequest(t)
		req.Add(stunmsg.AttrUsername, []byte(testUser))
		req.Add(stunmsg.AttrRealm, realm)
		req.Add(stunmsg.AttrNonce, nonce)
		mutate(req)
		req.AddMessageIntegritySHA256(stunmsg.LongTermKeySHA256(testUser, testRealm, testPass))
		return req.Marshal()
	}
	for name, pkt := range map[string][]byte{
		"PASSWORD-ALGORITHM without echo": build(func(m *stunmsg.Message) {
			m.AddPasswordAlgorithm(stunmsg.PasswordAlgorithmSHA256)
		}),
		"echo mismatch": build(func(m *stunmsg.Message) {
			m.AddPasswordAlgorithms([]uint16{stunmsg.PasswordAlgorithmMD5})
			m.AddPasswordAlgorithm(stunmsg.PasswordAlgorithmMD5)
		}),
		"chosen not in echo": build(func(m *stunmsg.Message) {
			m.AddPasswordAlgorithms([]uint16{stunmsg.PasswordAlgorithmSHA256, stunmsg.PasswordAlgorithmMD5})
			m.AddPasswordAlgorithm(0x7777)
		}),
	} {
		resp := roundTrip(t, client, pkt)
		if code := errorCode(t, resp); code != 400 {
			t.Fatalf("%s: error code = %d, want 400", name, code)
		}
		if _, ok := resp.Get(stunmsg.AttrNonce); ok {
			t.Fatalf("%s: 400 must not carry NONCE", name)
		}
	}
}

// Stripping the security-feature bits from the nonce (a bid-down attempt)
// must invalidate it: the request authenticates but draws a 438.
func TestAuthBidDownDetected(t *testing.T) {
	client := startAuthServer(t)
	realm, nonce := challenge(t, client)
	tampered := append([]byte(nil), nonce...)
	copy(tampered[9:13], "AAAA") // clear all feature bits
	resp := roundTrip(t, client, legacyRequest(t, realm, tampered, testUser, testPass, false))
	if code := errorCode(t, resp); code != 438 {
		t.Fatalf("error code = %d, want 438", code)
	}
}

func TestAuthStaleNonce(t *testing.T) {
	client := startAuthServer(t)
	realm, _ := challenge(t, client)
	expired := Credentials.nonce(time.Now().Add(-nonceTTL - time.Minute))
	resp := roundTrip(t, client, legacyRequest(t, realm, expired, testUser, testPass, false))
	if code := errorCode(t, resp); code != 438 {
		t.Fatalf("error code = %d, want 438", code)
	}
	if _, ok := resp.Get(stunmsg.AttrNonce); !ok {
		t.Fatal("438 response missing fresh NONCE")
	}

	// §9.2.4 orders the integrity check before nonce validity: an expired
	// nonce with bad credentials is a 401, not a 438.
	resp = roundTrip(t, client, legacyRequest(t, realm, expired, testUser, "wrong", false))
	if code := errorCode(t, resp); code != 401 {
		t.Fatalf("expired nonce + bad password: error code = %d, want 401", code)
	}
}

func TestAuthIntegrityWithoutUsernameIs400(t *testing.T) {
	client := startAuthServer(t)
	req := newRequest(t)
	req.AddMessageIntegrity([]byte("whatever"))
	resp := roundTrip(t, client, req.Marshal())
	if code := errorCode(t, resp); code != 400 {
		t.Fatalf("error code = %d, want 400", code)
	}
}
