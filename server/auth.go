package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"stun/stunmsg"
)

// Credentials, when non-nil, enables RFC 8489 §9.2 long-term credential
// authentication on all serve loops: requests must carry a valid
// MESSAGE-INTEGRITY(-SHA256) or are challenged with a 401. Set before Serve.
var Credentials *Auth

// nonceTTL is how long an issued nonce stays valid; after that a request
// using it draws a 438 Stale Nonce carrying a fresh one.
const nonceTTL = 5 * time.Minute

// Auth is the long-term credential configuration. Create with NewAuth.
type Auth struct {
	Realm  string
	Users  map[string]string // username → password
	secret []byte            // keys the stateless nonces
}

// NewAuth builds an Auth with a random nonce-signing secret. The secret is
// per-process: nonces don't survive a restart, which only costs clients one
// extra 438 round trip.
func NewAuth(realm string, users map[string]string) *Auth {
	secret := make([]byte, 32)
	rand.Read(secret)
	return &Auth{Realm: realm, Users: users, secret: secret}
}

// nonce returns hex(expiry ‖ HMAC-SHA256(secret, expiry)): self-
// authenticating, so validity is checked by recomputation — no per-client
// nonce table to store or to fill with garbage.
func (a *Auth) nonce(now time.Time) []byte {
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(now.Add(nonceTTL).Unix()))
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(exp[:])
	return []byte(hex.EncodeToString(mac.Sum(exp[:])))
}

func (a *Auth) nonceValid(v []byte, now time.Time) bool {
	b, err := hex.DecodeString(string(v))
	if err != nil || len(b) != 8+sha256.Size {
		return false
	}
	if uint64(now.Unix()) > binary.BigEndian.Uint64(b[:8]) {
		return false
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(b[:8])
	return hmac.Equal(mac.Sum(nil), b[8:])
}

// check runs the server side of RFC 8489 §9.2.4 on a request. Success
// returns the key the response must be signed with and whether the client
// used the SHA-256 variant; failure returns the error response to send
// instead (401 challenge, 438 stale nonce, or 400).
func (a *Auth) check(pkt []byte, req *stunmsg.Message) (key []byte, sha2 bool, errResp *stunmsg.Message) {
	_, sha2 = req.Get(stunmsg.AttrMessageIntegritySHA256)
	if _, sha1 := req.Get(stunmsg.AttrMessageIntegrity); !sha1 && !sha2 {
		return nil, false, a.challenge(req, 401, "Unauthorized")
	}
	user, uok := req.Get(stunmsg.AttrUsername)
	realm, rok := req.Get(stunmsg.AttrRealm)
	nonce, nok := req.Get(stunmsg.AttrNonce)
	if !uok || !rok || !nok {
		resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID}
		resp.AddErrorCode(400, "Bad Request")
		return nil, false, resp
	}
	if !a.nonceValid(nonce, time.Now()) {
		return nil, false, a.challenge(req, 438, "Stale Nonce")
	}
	password, known := a.Users[string(user)]
	if !known || string(realm) != a.Realm {
		return nil, false, a.challenge(req, 401, "Unauthorized")
	}
	key = stunmsg.LongTermKey(string(user), a.Realm, password)
	verify := stunmsg.VerifyMessageIntegrity
	if sha2 {
		verify = stunmsg.VerifyMessageIntegritySHA256
	}
	if !verify(pkt, key) {
		return nil, false, a.challenge(req, 401, "Unauthorized")
	}
	return key, sha2, nil
}

// challenge builds the error response that carries REALM and a fresh NONCE,
// giving the client what it needs to retry authenticated.
func (a *Auth) challenge(req *stunmsg.Message, code int, reason string) *stunmsg.Message {
	resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID}
	resp.AddErrorCode(code, reason)
	resp.Add(stunmsg.AttrRealm, []byte(a.Realm))
	resp.Add(stunmsg.AttrNonce, a.nonce(time.Now()))
	return resp
}

// authenticate applies Credentials to a request when set; anonymous
// servers pass everything through with no signing key.
func authenticate(pkt []byte, req *stunmsg.Message) (key []byte, sha2 bool, errResp *stunmsg.Message) {
	if Credentials == nil {
		return nil, false, nil
	}
	return Credentials.check(pkt, req)
}
