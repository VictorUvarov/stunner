package main

import (
	"crypto/tls"
	"log/slog"
	"os"
	"sync"
	"time"
)

// certLoader serves the TLS/DTLS key pair and reloads it from disk when the
// files change, so certificate rotation (e.g. certbot renewing a Let's
// Encrypt cert) needs no server restart. Both Go's TLS stack and pion/dtls
// consult a callback per handshake; the loader answers those from memory and
// re-stats the files at most once a second. A reload that fails to parse
// keeps serving the previous pair — a bad rotation shouldn't take down the
// listener that could outlive it.
type certLoader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	loaded  time.Time // newest mtime of the two files at last successful load
	checked time.Time
}

// newCertLoader loads the pair once, eagerly, so a typo'd path or garbage
// key still fails at startup.
func newCertLoader(certFile, keyFile string) (*certLoader, error) {
	l := &certLoader{certFile: certFile, keyFile: keyFile}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	l.cert = &cert
	l.loaded = l.mtime()
	l.checked = time.Now()
	return l, nil
}

// get returns the current certificate, reloading first if the files
// changed since the last successful load. Never returns an error after
// construction succeeds: a broken reload logs and serves the old pair.
func (l *certLoader) get() (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.checked) >= time.Second {
		l.checked = time.Now()
		if mt := l.mtime(); mt.After(l.loaded) {
			cert, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
			if err != nil {
				slog.Warn("certificate reload failed, keeping previous", "err", err)
			} else {
				l.cert = &cert
				l.loaded = mt
				slog.Info("certificate reloaded", "cert", l.certFile)
			}
		}
	}
	return l.cert, nil
}

// mtime returns the newer of the two files' modification times; a file we
// can't stat counts as unchanged (the reload would fail anyway, loudly).
func (l *certLoader) mtime() time.Time {
	var newest time.Time
	for _, f := range []string{l.certFile, l.keyFile} {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}
