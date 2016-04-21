package main // import "github.com/nutmegdevelopment/nutcracker-ui"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/nutmegdevelopment/nutcracker-ui/nutcracker"
)

var ciphers = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

func newCert(key *ecdsa.PrivateKey) (cert *x509.Certificate, err error) {
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "nutcracker-ui",
		},
		NotBefore:          time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:           time.Now().AddDate(1, 0, 0).UTC(),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return
	}
	return x509.ParseCertificate(derBytes)
}

func newKey() (key *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenCert creates a self-signed TLS cert.
func GenCert() (tlsCert tls.Certificate, err error) {
	key, err := newKey()
	if err != nil {
		return
	}

	cert, err := newCert(key)
	if err != nil {
		return
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if certBytes == nil {
		err = errors.New("Unable to encode cert")
		return
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: der,
	})
	if keyBytes == nil {
		err = errors.New("Unable to encode key")
		return
	}

	return tls.X509KeyPair(certBytes, keyBytes)
}

// LoadCert loads a cert from disk, given paths to the cert and key.
func LoadCert(cert, key string) (tlsCert tls.Certificate, err error) {
	return tls.LoadX509KeyPair(cert, key)
}

// Socket creates a TLS socket
func Socket(address string, cert tls.Certificate) (socket net.Listener, err error) {
	cfg := &tls.Config{
		Rand:                     nil, // Use crypto/rand
		CipherSuites:             ciphers,
		SessionTicketsDisabled:   false,
		ClientAuth:               tls.NoClientCert,
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{cert},
	}

	return tls.Listen("tcp", address, cfg)
}

// Taken from crypto/x509
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}

func GetNutcrackerCert(api *nutcracker.API) (cert tls.Certificate, err error) {
	buf, err := api.Post("/secrets/view", nutcracker.NewAPIReq().Set("name", nutcrackerCertName))
	if err != nil {
		return
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(buf)-8))
	n, err := base64.StdEncoding.Decode(decoded, buf[8:])

	decoded = decoded[:n]

	for len(decoded) > 0 {
		var block *pem.Block
		block, decoded = pem.Decode(decoded)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}

		if block.Type == "PRIVATE KEY" || strings.HasSuffix(block.Type, " PRIVATE KEY") {
			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				continue
			}
		}

	}

	return

}
