package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type certFiles struct {
	cert, key           []byte
	fingerprint, source string
}

func readLeaf(path string) (*x509.Certificate, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("ожидался сертификат в PEM")
	}
	return x509.ParseCertificate(p.Bytes)
}
func (i *installer) validatePair(o installOptions) (certFiles, error) {
	var out certFiles
	cert, e := os.ReadFile(o.cert)
	if e != nil {
		return out, e
	}
	key, e := os.ReadFile(o.key)
	if e != nil {
		return out, e
	}
	if o.chain != "" {
		chain, e := os.ReadFile(o.chain)
		if e != nil {
			return out, e
		}
		rest := bytes.TrimSpace(chain)
		if len(rest) == 0 {
			return out, fmt.Errorf("пустая цепочка")
		}
		for len(rest) > 0 {
			p, next := pem.Decode(rest)
			if p == nil || p.Type != "CERTIFICATE" {
				return out, fmt.Errorf("неверная цепочка PEM")
			}
			if _, e := x509.ParseCertificate(p.Bytes); e != nil {
				return out, e
			}
			rest = bytes.TrimSpace(next)
		}
		cert = append(append(cert, '\n'), chain...)
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return out, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return out, e
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return out, fmt.Errorf("сертификат вне срока действия %s — %s", iso(leaf.NotBefore), iso(leaf.NotAfter))
	}
	if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
		i.say("Сертификат истекает %s", iso(leaf.NotAfter))
	}
	if e = leaf.VerifyHostname(fqdn()); e != nil {
		i.say("Проверьте DNS-имя сервера в SAN: %v", e)
	}
	if len(pair.Certificate) == 1 && leaf.Issuer.String() != leaf.Subject.String() {
		i.say("Для передачи промежуточных сертификатов используйте --chain.")
	}
	return certFiles{cert, key, fmt.Sprintf("%x", sha256.Sum256(leaf.Raw)), o.cert}, nil
}

// The TLS peer is verified by comparing its leaf digest to the administrator-supplied certificate.
func servedFingerprint(port int) (string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, e := tls.DialWithDialer(
		&d,
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
	)
	if e != nil {
		return "", e
	}
	defer c.Close()
	cert := c.ConnectionState().PeerCertificates[0]
	return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), nil
}
func (i *installer) changeCert(ctx context.Context, port int, self bool, c certFiles) error {
	names := []string{"cert.pem", "key.pem", "cert.org"}
	if self && !fileExists(filepath.Join(i.dir, "cert.org")) {
		return nil
	}
	for _, n := range names {
		p := filepath.Join(i.dir, n)
		if st, e := os.Stat(p); e == nil {
			if e = copyFile(p, p+".prev", st.Mode().Perm()); e != nil {
				return e
			}
		} else if os.IsNotExist(e) {
			if err := os.Remove(p + ".prev"); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else {
			return e
		}
	}
	apply := func() error {
		if self {
			for _, n := range names {
				if e := os.Remove(filepath.Join(i.dir, n)); e != nil && !os.IsNotExist(e) {
					return e
				}
			}
		} else {
			if e := atomicFile(filepath.Join(i.dir, "key.pem"), c.key, 0600); e != nil {
				return e
			}
			if e := atomicFile(filepath.Join(i.dir, "cert.pem"), c.cert, 0644); e != nil {
				return e
			}
			marker := fmt.Sprintf(
				"installed=%s\nsource=%s\nsha256=%s\n",
				iso(time.Now()),
				strings.ReplaceAll(c.source, "\n", " "),
				c.fingerprint,
			)
			if e := atomicFile(filepath.Join(i.dir, "cert.org"), []byte(marker), 0644); e != nil {
				return e
			}
		}
		if e := i.restart(ctx); e != nil {
			return e
		}
		if e := i.wait(ctx, port, ""); e != nil {
			return e
		}
		if !self {
			fp, e := i.fingerprint(port)
			if e != nil {
				return e
			}
			if fp != c.fingerprint {
				return fmt.Errorf("служба предъявила другой сертификат")
			}
		}
		return nil
	}
	if e := apply(); e != nil {
		for _, n := range names {
			p := filepath.Join(i.dir, n)
			var err error
			if fileExists(p + ".prev") {
				err = os.Rename(p+".prev", p)
			} else {
				err = os.Remove(p)
			}
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("%v; не удалось восстановить %s: %w", e, p, err)
			}
		}
		if err := i.restart(ctx); err != nil {
			return fmt.Errorf("%v; перезапуск после отката: %w", e, err)
		}
		if err := i.wait(ctx, port, ""); err != nil {
			return fmt.Errorf("%v; проверка после отката: %w", e, err)
		}
		return fmt.Errorf("восстановлен прежний сертификат: %w", e)
	}
	if !self {
		for _, n := range names {
			os.Remove(filepath.Join(i.dir, n+".prev"))
		}
	}
	return nil
}
