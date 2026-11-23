package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type tlsState struct {
	mu            sync.RWMutex
	pair          *tls.Certificate
	leaf          *x509.Certificate
	mode, problem string
}

func (t *tlsState) current(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.pair == nil {
		return nil, fmt.Errorf("no TLS certificate")
	}
	return t.pair, nil
}
func (t *tlsState) status(now time.Time) fields {
	t.mu.RLock()
	defer t.mu.RUnlock()
	mode := t.mode
	if mode == "" {
		mode = "none"
	}
	var problem, cert any
	if t.problem != "" {
		problem = t.problem
	}
	if x := t.leaf; x != nil {
		cert = fields{
			"not_after": iso(x.NotAfter.UTC()),
			"days_left": int(x.NotAfter.Sub(now).Hours() / 24),
			"issuer":    x.Issuer.String(),
			"subject":   x.Subject.String(),
		}
	}
	return fields{"mode": mode, "error": problem, "certificate": cert}
}
func loadPair(cert, key string) (*tls.Certificate, *x509.Certificate, error) {
	p, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, nil, e
	}
	x, e := x509.ParseCertificate(p.Certificate[0])
	return &p, x, e
}
func generatePair(certPath, keyPath, host string, now time.Time) error {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else if host != "" {
		cert.DNSNames = append(cert.DNSNames, host)
		if short, _, ok := strings.Cut(host, "."); ok {
			cert.DNSNames = append(cert.DNSNames, short)
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	kd, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return e
	}
	if e = atomicFile(
		keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}),
		0600,
	); e != nil {
		return e
	}
	return atomicFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}
func (a *app) setupTLS() error {
	mode := "self-signed"
	problem := ""
	cert, key := filepath.Join(a.dir, "cert.pem"), filepath.Join(a.dir, "key.pem")
	pair, leaf, err := loadPair(cert, key)
	if fileExists(filepath.Join(a.dir, "cert.org")) {
		mode = "organization"
		if err != nil {
			mode = "fallback"
			problem = err.Error()
			cert, key = filepath.Join(a.dir, "cert-selfsigned.pem"), filepath.Join(a.dir, "key-selfsigned.pem")
			pair, leaf, err = loadPair(cert, key)
		}
	}
	if mode != "organization" && (err != nil || leaf.NotAfter.Sub(a.now()) < 30*24*time.Hour) {
		if err = generatePair(cert, key, a.host, a.now()); err == nil {
			pair, leaf, err = loadPair(cert, key)
		}
	}
	t := &a.certs
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.problem = err.Error()
		return err
	}
	t.pair, t.leaf, t.mode, t.problem = pair, leaf, mode, problem
	return nil
}
