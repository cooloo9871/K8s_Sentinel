package webhook

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

type CertBundle struct {
	CACert     []byte // PEM-encoded CA cert (injected into webhook caBundle)
	ServerCert []byte // PEM-encoded server cert
	ServerKey  []byte // PEM-encoded server key
}

// LoadOrCreate loads existing TLS files or generates a new self-signed bundle.
func LoadOrCreate(certFile, keyFile, caFile string, dnsNames []string) (*CertBundle, error) {
	// Try loading existing
	if b, err := loadExisting(certFile, keyFile, caFile); err == nil {
		return b, nil
	}
	// Generate new
	b, err := generateBundle(dnsNames)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certFile, b.ServerCert, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, b.ServerKey, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(caFile, b.CACert, 0600); err != nil {
		return nil, err
	}
	return b, nil
}

func loadExisting(certFile, keyFile, caFile string) (*CertBundle, error) {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	// Verify cert is still valid
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, os.ErrInvalid
	}
	x, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if time.Now().After(x.NotAfter.Add(-24 * time.Hour)) {
		return nil, os.ErrInvalid // renew if expiring within 24h
	}
	return &CertBundle{CACert: ca, ServerCert: cert, ServerKey: key}, nil
}

func generateBundle(dnsNames []string) (*CertBundle, error) {
	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Sentinel CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// Generate server key
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Sentinel"}},
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	// PEM encode
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	return &CertBundle{CACert: caPEM, ServerCert: srvCertPEM, ServerKey: srvKeyPEM}, nil
}

// TLSConfig returns a *tls.Config using the bundle.
func (b *CertBundle) TLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(b.ServerCert, b.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
