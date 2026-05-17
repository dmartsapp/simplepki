package simplepki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type AssetType string

const (
	TypeUnknown AssetType = "UNKNOWN"
	TypeCRT     AssetType = "CERTIFICATE"
	TypeCSR     AssetType = "CERTIFICATE REQUEST"
	TypePrivate AssetType = "PRIVATE KEY"
	TypePublic  AssetType = "PUBLIC KEY"
)

var (
	_COUNTRIES  = []string{"CA", "BD", "US", "UK"}
	_COMMONNAME = "sepcot.dmarts.app"
)

const ()

type SimplePKI struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func New(bits int) (*SimplePKI, error) {
	if priv, err := generateKeyPair(bits); err != nil {
		return nil, err
	} else {
		var pki = SimplePKI{
			privateKey: priv,
			publicKey:  &priv.PublicKey,
		}
		return &pki, nil
	}
}

func (simplepki *SimplePKI) GetPrivateKey() *rsa.PrivateKey {
	return simplepki.privateKey
}

func (simplepki *SimplePKI) GetPublicKey() *rsa.PublicKey {
	return simplepki.publicKey
}

func (simplepki *SimplePKI) GenerateCSR(commonname string, dnsnames []string) ([]byte, error) {
	if csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA512WithRSA,
		Subject: pkix.Name{
			Country:      _COUNTRIES,
			CommonName:   commonname,
			Organization: []string{commonname},
		},
		DNSNames: dnsnames}, simplepki.privateKey); err != nil {
		return nil, err
	} else {
		return csr, nil
	}
}

func (simplepki *SimplePKI) SignCSR(csrBytes []byte, notAfterDays int, asCA bool, parentCertificate *x509.Certificate) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, notAfterDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              csr.DNSNames,
		BasicConstraintsValid: true,
		IsCA:                  asCA,
	}
	parentCert := &certTemplate
	if parentCertificate != nil {
		parentCert = parentCertificate
	}
	subjectKeyId := sha1.Sum(x509.MarshalPKCS1PublicKey(csr.PublicKey.(*rsa.PublicKey)))
	certTemplate.SubjectKeyId = subjectKeyId[:]
	if asCA {
		certTemplate.KeyUsage |= x509.KeyUsageCertSign
	}
	if crt, err := x509.CreateCertificate(rand.Reader, &certTemplate, parentCert, csr.PublicKey, simplepki.privateKey); err != nil {
		return nil, err
	} else {
		return crt, nil
	}
}

func (simplePKI *SimplePKI) GetPEM(x509Object any) ([]byte, error) {
	var derBytes []byte
	var err error
	switch v := x509Object.(type) {
	case *rsa.PrivateKey:
		derBytes, err = x509.MarshalPKCS8PrivateKey(v)
		if err != nil {
			return nil, err
		}

	case *rsa.PublicKey:
		derBytes, err = x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return nil, err
		}

	case *x509.Certificate:
		derBytes = v.Raw

	case *x509.CertificateRequest:
		derBytes = v.Raw

	case []byte:
		derBytes = v

	default:
		return nil, fmt.Errorf("Unknown data format")
	}

	if len(derBytes) < 16 {
		return nil, fmt.Errorf("byte slice too short to safely analyze")
	}

	if derBytes[0] != 0x30 {
		return nil, fmt.Errorf("invalid file format: missing root sequence tag")
	}

	// 1. Calculate past the outer envelope length
	var innerIdx int
	if derBytes[1] == 0x82 {
		innerIdx = 4
	} else if derBytes[1] == 0x81 {
		innerIdx = 3
	} else {
		innerIdx = 2
	}

	detectedType := "UNKNOWN"

	// 2. Evaluate Layer 2 Container Types
	if derBytes[innerIdx] == 0x30 {
		// Both Public Keys and Certificates pass through this branch.
		// Skip past this second inner sequence's length bytes to inspect Layer 3.
		var layer3Idx int
		if derBytes[innerIdx+1] == 0x82 {
			layer3Idx = innerIdx + 4
		} else if derBytes[innerIdx+1] == 0x81 {
			layer3Idx = innerIdx + 3
		} else {
			layer3Idx = innerIdx + 2
		}

		if layer3Idx < len(derBytes) {
			switch derBytes[layer3Idx] {
			case 0x02:
				// If it's an integer block at Layer 3, we look for the CSR signature (0x02 0x01 0x00)
				if layer3Idx+2 < len(derBytes) && derBytes[layer3Idx+1] == 0x01 && derBytes[layer3Idx+2] == 0x00 {
					detectedType = "CERTIFICATE REQUEST"
				} else {
					detectedType = "CERTIFICATE"
				}
			case 0xA0:
				// 0xA0 is an ASN.1 Explicit Tag [0].
				// Modern X.509 v3 certificates open their TBSCertificate with this exact tag to flag the version context.
				detectedType = "CERTIFICATE"
			case 0x30:
				// If it embeds yet another sequence layer, it's the algorithm wrapper of a Public Key
				detectedType = "PUBLIC KEY"
			default:
				// Fallback context: Default to Public Key if standard certificate markers are absent
				detectedType = "PUBLIC KEY"
			}
		}

		type Fork0x02 struct{} // Label marker block
	} else if derBytes[innerIdx] == 0x02 {
		// Private keys and un-nested blocks open directly with an integer flag
		if innerIdx+2 < len(derBytes) && derBytes[innerIdx+1] == 0x01 && derBytes[innerIdx+2] == 0x00 {
			detectedType = "PRIVATE KEY"
		} else {
			detectedType = "CERTIFICATE"
		}
	}

	if detectedType == "UNKNOWN" {
		return nil, fmt.Errorf("unable to reliably detect cryptographic asset type")
	}

	block := &pem.Block{
		Type:  detectedType,
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

func generateKeyPair(bits int) (*rsa.PrivateKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	} else {
		return privkey, nil
	}
}
