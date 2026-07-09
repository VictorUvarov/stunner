package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/text/secure/precis"

	"stun/internal/stunmsg"
)

// Credentials enables RFC 8489 §9.2 long-term credential authentication on
// all serve loops when non-nil: requests must carry a valid
// MESSAGE-INTEGRITY(-SHA256) or are challenged with a 401. Set before Serve.
var Credentials *Auth

// nonceTTL is how long an issued nonce stays valid; after that an
// otherwise-authenticated request draws a 438 carrying a fresh one.
const nonceTTL = 5 * time.Minute

// nonceCookie prefixes every nonce (RFC 8489 §9.2): "obMatJos2" plus the
// base64 of the 24-bit security-feature set, which bid-down-protects the
// features we support — "Password algorithms" (bit 0) and "Username
// anonymity" (bit 1). Bit 0 is the RIGHTMOST bit: the RFC's §18.1 prose
// says leftmost, but verified erratum 6290 and the B.1 test vector agree
// on rightmost.
var nonceCookie = "obMatJos2" + base64.StdEncoding.EncodeToString([]byte{0, 0, 0b11})

// passwordAlgorithms is what the server offers in challenges, in
// preference order (RFC 8489 §18.5).
var passwordAlgorithms = []uint16{stunmsg.PasswordAlgorithmSHA256, stunmsg.PasswordAlgorithmMD5}

// credential holds the derived keys for one user; raw passwords are not
// retained.
type credential struct {
	keyMD5, keySHA256 []byte
}

// key returns the response-signing key for the negotiated password algorithm.
func (c credential) key(alg uint16) []byte {
	if alg == stunmsg.PasswordAlgorithmSHA256 {
		return c.keySHA256
	}
	return c.keyMD5
}

// verifyIntegrity checks pkt against key using MESSAGE-INTEGRITY-SHA256 when
// sha2 is set, else legacy MESSAGE-INTEGRITY.
func verifyIntegrity(pkt, key []byte, sha2 bool) bool {
	if sha2 {
		return stunmsg.VerifyMessageIntegritySHA256(pkt, key)
	}
	return stunmsg.VerifyMessageIntegrity(pkt, key)
}

// Auth is the long-term credential configuration. Create with NewAuth.
type Auth struct {
	Realm  string
	users  map[string]credential // by OpaqueString-processed username
	byHash map[[32]byte]string   // USERHASH value → username
	secret []byte                // keys the stateless nonces
}

// NewAuth builds an Auth, applying the OpaqueString profile (RFC 8265) to
// the realm and every username and password as §9.2.2 requires, and
// pre-deriving the MD5 and SHA-256 keys plus the USERHASH lookup table.
// The nonce secret is per-process: nonces don't survive a restart, which
// only costs clients one extra 438 round trip.
func NewAuth(realm string, users map[string]string) (*Auth, error) {
	realm, err := precis.OpaqueString.String(realm)
	if err != nil {
		return nil, fmt.Errorf("realm: %w", err)
	}
	a := &Auth{
		Realm:  realm,
		users:  make(map[string]credential, len(users)),
		byHash: make(map[[32]byte]string, len(users)),
		secret: make([]byte, 32),
	}
	rand.Read(a.secret)
	for u, p := range users {
		if u, err = precis.OpaqueString.String(u); err != nil {
			return nil, fmt.Errorf("username %q: %w", u, err)
		}
		if p, err = precis.OpaqueString.String(p); err != nil {
			return nil, fmt.Errorf("password for %q: %w", u, err)
		}
		a.users[u] = credential{
			keyMD5:    stunmsg.LongTermKey(u, realm, p),
			keySHA256: stunmsg.LongTermKeySHA256(u, realm, p),
		}
		a.byHash[[32]byte(stunmsg.Userhash(u, realm))] = u
	}
	return a, nil
}

// nonce returns nonceCookie ‖ hex(expiry ‖ HMAC-SHA256(secret, expiry)):
// self-authenticating, so validity is checked by recomputation — no
// per-client nonce table to store or to fill with garbage.
func (a *Auth) nonce(now time.Time) []byte {
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(now.Add(nonceTTL).Unix()))
	mac := hmac.New(sha256.New, a.secret)
	mac.Write(exp[:])
	return append([]byte(nonceCookie), hex.EncodeToString(mac.Sum(exp[:]))...)
}

func (a *Auth) nonceValid(v []byte, now time.Time) bool {
	s, ok := strings.CutPrefix(string(v), nonceCookie)
	if !ok {
		return false // includes tampered feature bits — bid-down detection
	}
	b, err := hex.DecodeString(s)
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

// passwordAlgorithmsBit reports whether nonce carries a nonce cookie with
// the "Password algorithms" security feature set — the trigger for the
// negotiation checks of §9.2.4, tested on the request's nonce as presented
// (a legacy client echoes our nonce untouched, so the bit survives).
func passwordAlgorithmsBit(nonce []byte) bool {
	if len(nonce) < 13 || string(nonce[:9]) != "obMatJos2" {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(string(nonce[9:13]))
	return err == nil && len(b) == 3 && b[2]&1 != 0
}

// check runs the server side of RFC 8489 §9.2.4 on a request, performing
// its checks in the order the RFC specifies (note that a stale nonce is
// only reported on an otherwise-authenticated request). Success returns
// the key the response must be signed with and whether the client
// negotiated a password algorithm — which per §9.2.4 decides whether the
// response carries MESSAGE-INTEGRITY-SHA256 or legacy MESSAGE-INTEGRITY.
// Failure returns the error response to send instead.
func (a *Auth) check(pkt []byte, req *stunmsg.Message) (key []byte, sha2 bool, errResp *stunmsg.Message) {
	_, mi256 := req.Get(stunmsg.AttrMessageIntegritySHA256)
	if _, mi1 := req.Get(stunmsg.AttrMessageIntegrity); !mi1 && !mi256 {
		return nil, false, a.challenge(req, 401, "Unauthenticated")
	}

	user, hasUser := req.Get(stunmsg.AttrUsername)
	uhash, hasHash := req.Get(stunmsg.AttrUserhash)
	realm, hasRealm := req.Get(stunmsg.AttrRealm)
	nonce, hasNonce := req.Get(stunmsg.AttrNonce)
	if (!hasUser && !hasHash) || !hasRealm || !hasNonce {
		return nil, false, bare400(req)
	}

	alg, negotiated, ok := negotiatePasswordAlgorithm(req, nonce)
	if !ok {
		return nil, false, bare400(req)
	}

	username := string(user)
	if !hasUser {
		if len(uhash) != 32 {
			return nil, false, a.challenge(req, 401, "Unauthenticated")
		}
		username = a.byHash[[32]byte(uhash)] // miss leaves "", not a user
	}
	cred, known := a.users[username]
	if !known || string(realm) != a.Realm {
		return nil, false, a.challenge(req, 401, "Unauthenticated")
	}

	key = cred.key(alg)
	if !verifyIntegrity(pkt, key, mi256) {
		return nil, false, a.challenge(req, 401, "Unauthenticated")
	}

	if !a.nonceValid(nonce, time.Now()) {
		return nil, false, a.challenge(req, 438, "Stale Nonce")
	}
	return key, negotiated, nil
}

// negotiatePasswordAlgorithm applies RFC 8489 §9.2.4 password-algorithm
// negotiation, guarded by the feature bit in the echoed nonce. It returns the
// algorithm the response key must use, whether the client negotiated one, and
// ok=false if the offered/chosen attributes are malformed or inconsistent (a
// 400). Absent both attributes — or the feature bit — the request is processed
// as though PASSWORD-ALGORITHM were MD5 (legacy client).
func negotiatePasswordAlgorithm(req *stunmsg.Message, nonce []byte) (alg uint16, negotiated, ok bool) {
	alg = uint16(stunmsg.PasswordAlgorithmMD5)
	if !passwordAlgorithmsBit(nonce) {
		return alg, false, true
	}
	offered, err := req.PasswordAlgorithms()
	chosen, hasChosen := req.PasswordAlgorithm()
	if offered == nil && !hasChosen {
		return alg, false, true
	}
	if err != nil || offered == nil || !hasChosen ||
		!slices.Equal(offered, passwordAlgorithms) ||
		!slices.Contains(offered, chosen) {
		return alg, false, false
	}
	return chosen, true, true
}

// challenge builds the error response that carries REALM, a fresh NONCE,
// and our PASSWORD-ALGORITHMS — everything a client needs to retry
// authenticated.
func (a *Auth) challenge(req *stunmsg.Message, code int, reason string) *stunmsg.Message {
	resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID}
	resp.AddErrorCode(code, reason)
	resp.Add(stunmsg.AttrRealm, []byte(a.Realm))
	resp.Add(stunmsg.AttrNonce, a.nonce(time.Now()))
	resp.AddPasswordAlgorithms(passwordAlgorithms)
	return resp
}

// bare400 is the 400 of §9.2.4, which must not carry REALM or NONCE.
func bare400(req *stunmsg.Message) *stunmsg.Message {
	resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID}
	resp.AddErrorCode(400, "Bad Request")
	return resp
}

// authenticate applies Credentials to a request when set; anonymous
// servers pass everything through with no signing key. Classic (RFC 3489)
// clients predate long-term credentials entirely, so on an auth-enabled
// server they draw a bare 401 — sending them REALM/NONCE would only feed
// mandatory attributes to a parser that must reject them.
func authenticate(pkt []byte, req *stunmsg.Message) (key []byte, sha2 bool, errResp *stunmsg.Message) {
	if Credentials == nil {
		return nil, false, nil
	}
	if req.Classic() {
		resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID, Cookie: req.Cookie}
		resp.AddErrorCode(401, "Unauthenticated")
		return nil, false, resp
	}
	return Credentials.check(pkt, req)
}
