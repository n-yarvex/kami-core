package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ECHKey struct {
	Config string `json:"config"`
	Key    string `json:"key"`
	Retry  bool   `json:"retry,omitempty"`
}

type Server struct {
	Certificate string   `json:"certificate,omitempty"`
	Key         string   `json:"key,omitempty"`
	SelfSigned  []string `json:"self_signed,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	MinVersion  string   `json:"min_version,omitempty"`
	ECHKeys     []ECHKey `json:"ech_keys,omitempty"`
}

type Client struct {
	ServerName string   `json:"server_name,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	Pins       []string `json:"pins,omitempty"`
	CA         []string `json:"ca,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	MinVersion string   `json:"min_version,omitempty"`
	ECHConfig  string   `json:"ech_config,omitempty"`
}

func version(s string, def uint16) (uint16, error) {
	switch s {
	case "":
		return def, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("tls: unsupported min_version %q", s)
}

func PinOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func NormalizePin(p string) (string, error) {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
	raw, err := hex.DecodeString(p)
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("tls: pin %q is not a sha256 hex digest", p)
	}
	return p, nil
}

func LeafPin(cfg *tls.Config) string {
	if len(cfg.Certificates) == 0 || cfg.Certificates[0].Leaf == nil {
		return ""
	}
	return PinOf(cfg.Certificates[0].Leaf)
}

var recheck = 10 * time.Second

type reloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	stamp             [2]time.Time
	checked           time.Time
}

func (r *reloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.checked) < recheck {
		return r.cert, nil
	}
	r.checked = time.Now()
	a, errA := os.Stat(r.certFile)
	b, errB := os.Stat(r.keyFile)
	if errA != nil || errB != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, errors.Join(errA, errB)
	}
	if r.cert != nil && a.ModTime().Equal(r.stamp[0]) && b.ModTime().Equal(r.stamp[1]) {
		return r.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, err
	}
	if pair.Leaf == nil {
		pair.Leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	}
	r.cert, r.stamp = &pair, [2]time.Time{a.ModTime(), b.ModTime()}
	return r.cert, nil
}

func (s Server) Config() (*tls.Config, error) {
	min, err := version(s.MinVersion, tls.VersionTLS12)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:                  min,
		NextProtos:                  append([]string(nil), s.ALPN...),
		DynamicRecordSizingDisabled: true,
	}
	switch {
	case s.Certificate != "" || s.Key != "":
		if s.Certificate == "" || s.Key == "" {
			return nil, errors.New("tls: certificate and key must be given together")
		}
		r := &reloader{certFile: s.Certificate, keyFile: s.Key}
		if _, err := r.get(nil); err != nil {
			return nil, fmt.Errorf("tls: load certificate: %w", err)
		}
		cfg.GetCertificate = r.get
	case len(s.SelfSigned) > 0:
		cert, err := selfSigned(s.SelfSigned)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	default:
		return nil, errors.New("tls: need certificate+key or self_signed")
	}
	for i, k := range s.ECHKeys {
		conf, err := base64.StdEncoding.DecodeString(k.Config)
		if err != nil {
			return nil, fmt.Errorf("tls: ech_keys[%d].config: %w", i, err)
		}
		priv, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			return nil, fmt.Errorf("tls: ech_keys[%d].key: %w", i, err)
		}
		cfg.EncryptedClientHelloKeys = append(cfg.EncryptedClientHelloKeys, tls.EncryptedClientHelloKey{
			Config: conf, PrivateKey: priv, SendAsRetry: k.Retry,
		})
	}
	if len(cfg.EncryptedClientHelloKeys) > 0 {
		cfg.MinVersion = max(cfg.MinVersion, tls.VersionTLS13)
	}
	return cfg, nil
}

func (c Client) Config(host string) (*tls.Config, error) {
	min, err := version(c.MinVersion, tls.VersionTLS12)
	if err != nil {
		return nil, err
	}
	name := c.ServerName
	if name == "" && net.ParseIP(host) == nil {
		name = host
	}
	cfg := &tls.Config{
		ServerName:                  name,
		MinVersion:                  min,
		NextProtos:                  append([]string(nil), c.ALPN...),
		InsecureSkipVerify:          c.Insecure,
		DynamicRecordSizingDisabled: true,
		ClientSessionCache:          tls.NewLRUClientSessionCache(32),
	}
	if c.ECHConfig != "" {
		list, err := base64.StdEncoding.DecodeString(c.ECHConfig)
		if err != nil {
			return nil, fmt.Errorf("tls: ech_config: %w", err)
		}
		if name == "" {
			return nil, errors.New("tls: ech_config needs server_name")
		}
		cfg.EncryptedClientHelloConfigList = list
		cfg.MinVersion = max(cfg.MinVersion, tls.VersionTLS13)
	}
	if len(c.CA) > 0 {
		pool := x509.NewCertPool()
		for _, path := range c.CA {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("tls: read ca: %w", err)
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("tls: no certificate in %s", path)
			}
		}
		cfg.RootCAs = pool
	}
	if len(c.Pins) > 0 {
		pins := make(map[string]struct{}, len(c.Pins))
		for _, p := range c.Pins {
			n, err := NormalizePin(p)
			if err != nil {
				return nil, err
			}
			pins[n] = struct{}{}
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("tls: server sent no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if _, ok := pins[PinOf(leaf)]; !ok {
				return errors.New("tls: server certificate does not match any pin")
			}
			return nil
		}
	} else if name == "" && !c.Insecure {
		return nil, errors.New("tls: server_name, pins or insecure is required when the server is an address")
	}
	return cfg, nil
}

func selfSigned(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func WritePair(dir string, names ...string) (certPath, keyPath, pin string, err error) {
	cert, err := selfSigned(names)
	if err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return "", "", "", err
	}
	certPath, keyPath = dir+"/cert.pem", dir+"/key.pem"
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o644); err != nil {
		return
	}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath, PinOf(cert.Leaf), err
}
