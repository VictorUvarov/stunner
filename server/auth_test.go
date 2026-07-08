package server

import (
	"net"
	"testing"
	"time"

	"stun/stunmsg"
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
	Credentials = NewAuth(testRealm, map[string]string{testUser: testPass})
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
	return realm, nonce
}

// signed builds an authenticated Binding Request.
func signed(t *testing.T, realm, nonce []byte, user, pass string, sha2 bool) []byte {
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

func TestAuthHandshake(t *testing.T) {
	for _, sha2 := range []bool{false, true} {
		client := startAuthServer(t)
		realm, nonce := challenge(t, client)
		if string(realm) != testRealm {
			t.Fatalf("realm = %q", realm)
		}

		raw := roundTripRaw(t, client, signed(t, realm, nonce, testUser, testPass, sha2))
		resp, err := stunmsg.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Type != stunmsg.BindingSuccess {
			t.Fatalf("sha2=%v: type = %v, want success", sha2, resp)
		}
		if _, err := resp.XORMappedAddress(); err != nil {
			t.Fatal(err)
		}
		// The response must be integrity-protected with the same key and
		// the same variant the client used.
		key := stunmsg.LongTermKey(testUser, testRealm, testPass)
		verify := stunmsg.VerifyMessageIntegrity
		if sha2 {
			verify = stunmsg.VerifyMessageIntegritySHA256
		}
		if !verify(raw, key) {
			t.Fatalf("sha2=%v: response integrity did not verify", sha2)
		}
	}
}

func TestAuthWrongPassword(t *testing.T) {
	client := startAuthServer(t)
	realm, nonce := challenge(t, client)
	resp := roundTrip(t, client, signed(t, realm, nonce, testUser, "wrong", false))
	if code := errorCode(t, resp); code != 401 {
		t.Fatalf("error code = %d, want 401", code)
	}
}

func TestAuthUnknownUser(t *testing.T) {
	client := startAuthServer(t)
	realm, nonce := challenge(t, client)
	resp := roundTrip(t, client, signed(t, realm, nonce, "mallory", testPass, false))
	if code := errorCode(t, resp); code != 401 {
		t.Fatalf("error code = %d, want 401", code)
	}
}

func TestAuthStaleNonce(t *testing.T) {
	client := startAuthServer(t)
	realm, _ := challenge(t, client)
	expired := Credentials.nonce(time.Now().Add(-nonceTTL - time.Minute))
	resp := roundTrip(t, client, signed(t, realm, expired, testUser, testPass, false))
	if code := errorCode(t, resp); code != 438 {
		t.Fatalf("error code = %d, want 438", code)
	}
	if _, ok := resp.Get(stunmsg.AttrNonce); !ok {
		t.Fatal("438 response missing fresh NONCE")
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
