package tlsx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

type UClient struct {
	Client
	Fingerprint string `json:"fingerprint,omitempty"`
}

var fingerprints = map[string]utls.ClientHelloID{
	"chrome":         utls.HelloChrome_Auto,
	"chrome_58":      utls.HelloChrome_58,
	"chrome_62":      utls.HelloChrome_62,
	"chrome_70":      utls.HelloChrome_70,
	"chrome_72":      utls.HelloChrome_72,
	"chrome_83":      utls.HelloChrome_83,
	"chrome_87":      utls.HelloChrome_87,
	"chrome_96":      utls.HelloChrome_96,
	"chrome_100":     utls.HelloChrome_100,
	"chrome_102":     utls.HelloChrome_102,
	"chrome_106":     utls.HelloChrome_106_Shuffle,
	"chrome_112_psk": utls.HelloChrome_112_PSK_Shuf,
	"chrome_114_psk": utls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome_115_pq":  utls.HelloChrome_115_PQ,
	"chrome_120":     utls.HelloChrome_120,
	"chrome_120_pq":  utls.HelloChrome_120_PQ,
	"chrome_131":     utls.HelloChrome_131,
	"chrome_133":     utls.HelloChrome_133,
	"firefox":        utls.HelloFirefox_Auto,
	"firefox_55":     utls.HelloFirefox_55,
	"firefox_56":     utls.HelloFirefox_56,
	"firefox_63":     utls.HelloFirefox_63,
	"firefox_65":     utls.HelloFirefox_65,
	"firefox_99":     utls.HelloFirefox_99,
	"firefox_102":    utls.HelloFirefox_102,
	"firefox_105":    utls.HelloFirefox_105,
	"firefox_120":    utls.HelloFirefox_120,
	"safari":         utls.HelloSafari_Auto,
	"safari_16":      utls.HelloSafari_16_0,
	"ios":            utls.HelloIOS_Auto,
	"ios_11":         utls.HelloIOS_11_1,
	"ios_12":         utls.HelloIOS_12_1,
	"ios_13":         utls.HelloIOS_13,
	"ios_14":         utls.HelloIOS_14,
	"android":        utls.HelloAndroid_11_OkHttp,
	"edge":           utls.HelloEdge_Auto,
	"edge_85":        utls.HelloEdge_85,
	"edge_106":       utls.HelloEdge_106,
	"360":            utls.Hello360_Auto,
	"qq":             utls.HelloQQ_Auto,
	"random":         utls.HelloRandomizedALPN,
	"random_no_alpn": utls.HelloRandomizedNoALPN,
	"random_full":    utls.HelloRandomized,
}

func Fingerprints() []string {
	out := make([]string, 0, len(fingerprints))
	for k := range fingerprints {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c UClient) hello() (utls.ClientHelloID, bool, error) {
	name := strings.ToLower(strings.TrimSpace(c.Fingerprint))
	if name == "" || name == "go" {
		return utls.ClientHelloID{}, false, nil
	}
	id, ok := fingerprints[name]
	if !ok {
		return utls.ClientHelloID{}, false, fmt.Errorf("tls: unknown fingerprint %q (known: %s)", c.Fingerprint, strings.Join(Fingerprints(), ", "))
	}
	return id, true, nil
}

func (c UClient) Validate(host string) error {
	if _, _, err := c.hello(); err != nil {
		return err
	}
	if c.Fingerprint != "" && c.ECHConfig != "" {
		return errors.New("tls: ech_config cannot be combined with fingerprint")
	}
	_, err := c.Config(host)
	return err
}

func (c UClient) Handshake(ctx context.Context, raw net.Conn, host string, alpn []string) (net.Conn, error) {
	id, spoof, err := c.hello()
	if err != nil {
		return nil, err
	}
	if spoof && c.ECHConfig != "" {
		return nil, errors.New("tls: ech_config cannot be combined with fingerprint")
	}
	cfg, err := c.Config(host)
	if err != nil {
		return nil, err
	}
	if len(alpn) > 0 {
		cfg.NextProtos = append([]string(nil), alpn...)
	}
	if !spoof {
		conn := tls.Client(raw, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return conn, nil
	}
	ucfg := &utls.Config{
		ServerName:            cfg.ServerName,
		InsecureSkipVerify:    cfg.InsecureSkipVerify,
		RootCAs:               cfg.RootCAs,
		VerifyPeerCertificate: cfg.VerifyPeerCertificate,
		MinVersion:            cfg.MinVersion,
		NextProtos:            cfg.NextProtos,
	}
	var conn *utls.UConn
	switch id {
	case utls.HelloRandomized, utls.HelloRandomizedALPN, utls.HelloRandomizedNoALPN:
		if len(alpn) > 0 {
			id = utls.HelloRandomizedNoALPN
			ucfg.NextProtos = nil
		}
		conn = utls.UClient(raw, ucfg, id)
	default:
		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return nil, fmt.Errorf("tls: fingerprint %q: %w", c.Fingerprint, err)
		}
		if len(alpn) > 0 {
			for _, ext := range spec.Extensions {
				if a, ok := ext.(*utls.ALPNExtension); ok {
					a.AlpnProtocols = append([]string(nil), alpn...)
				}
			}
		}
		conn = utls.UClient(raw, ucfg, utls.HelloCustom)
		if err := conn.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("tls: fingerprint %q: %w", c.Fingerprint, err)
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}
