package simplepki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// AssetType represents the identified type of a cryptographic object.
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

// CSROptions provides granular control over identity details during CSR construction.
type CSROptions struct {
	CommonName   string
	Organization []string
	OrgUnit      []string
	Countries    []string
	Locality     []string
	Province     []string
	DNSNames     []string
	IPAddresses  []net.IP // Allows direct IP routing validation
}

// CertificateOptions configures constraints and policies during the signing process.
type CertificateOptions struct {
	NotAfterDays       int
	AsCA               bool
	MaxPathLen         int                // Only used if AsCA is true. 0 means can only sign leaf certs.
	ExtKeyUsages       []x509.ExtKeyUsage // e.g., ServerAuth, ClientAuth
	SignatureAlgorithm x509.SignatureAlgorithm
}

// SimplePKI holds the RSA key pair used for signing and identification.
type SimplePKI struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	rawCertDER []byte // cache the current certificate DER
}

// New creates a new SimplePKI instance with a generated RSA key pair.
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

// SetCertificate explicitly associates a pre-signed DER cert with this instance.
func (simplepki *SimplePKI) SetCertificate(derBytes []byte) {
	simplepki.rawCertDER = derBytes
}

// GetPrivateKey returns the underlying RSA private key.
func (simplepki *SimplePKI) GetPrivateKey() *rsa.PrivateKey {
	return simplepki.privateKey
}

// GetPublicKey returns the underlying RSA public key.
func (simplepki *SimplePKI) GetPublicKey() *rsa.PublicKey {
	return simplepki.publicKey
}

// GenerateCertificateSigningRequest creates a raw DER-encoded CSR using extensible options.
func (simplepki *SimplePKI) GenerateCertificateSigningRequest(opts CSROptions) ([]byte, error) {
	countries := opts.Countries
	if len(countries) == 0 {
		countries = _COUNTRIES
	}

	subject := pkix.Name{
		Country:      countries,
		CommonName:   opts.CommonName,
		Organization: opts.Organization,
	}
	if len(opts.OrgUnit) > 0 {
		subject.OrganizationalUnit = opts.OrgUnit
	}
	if len(opts.Locality) > 0 {
		subject.Locality = opts.Locality
	}
	if len(opts.Province) > 0 {
		subject.Province = opts.Province
	}

	csrTemplate := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA512WithRSA,
		Subject:            subject,
		DNSNames:           opts.DNSNames,
		IPAddresses:        opts.IPAddresses,
	}

	if csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, simplepki.privateKey); err != nil {
		return nil, err
	} else {
		return csr, nil
	}
}

// SignCertificate signs a CSR and returns a DER-encoded certificate utilizing dynamic parameters.
// If parentCertificate is nil, it runs a self-signed transaction.
func (simplepki *SimplePKI) SignCertificate(csrBytes []byte, opts CertificateOptions, parentCertificate *x509.Certificate) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// Default to standard Server/Client security patterns if none specified
	extUsages := opts.ExtKeyUsages
	if len(extUsages) == 0 {
		extUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	sigAlgo := opts.SignatureAlgorithm
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		sigAlgo = x509.SHA512WithRSA
	}

	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, opts.NotAfterDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extUsages,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses, // Pass through IP SANs claims safely
		BasicConstraintsValid: true,
		IsCA:                  opts.AsCA,
		SignatureAlgorithm:    sigAlgo,
	}

	// Manage Path Length Limitations for CA hierarchies
	if opts.AsCA {
		certTemplate.MaxPathLen = opts.MaxPathLen
		certTemplate.MaxPathLenZero = opts.MaxPathLen == 0
	}

	parentCert := &certTemplate
	if parentCertificate != nil {
		parentCert = parentCertificate
		certTemplate.AuthorityKeyId = parentCertificate.SubjectKeyId
	}

	subjectKeyId := sha1.Sum(x509.MarshalPKCS1PublicKey(csr.PublicKey.(*rsa.PublicKey)))
	certTemplate.SubjectKeyId = subjectKeyId[:]
	if opts.AsCA {
		certTemplate.KeyUsage |= x509.KeyUsageCertSign
	}

	crt, err := x509.CreateCertificate(rand.Reader, &certTemplate, parentCert, csr.PublicKey, simplepki.privateKey)
	if err != nil {
		return nil, err
	}

	csrPubKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if parentCertificate == nil || (ok && simplepki.publicKey.E == csrPubKey.E && simplepki.publicKey.N.Cmp(csrPubKey.N) == 0) {
		simplepki.rawCertDER = crt
	}
	return crt, nil
}

// GetPEM takes an x509 object or raw bytes and returns the PEM-encoded representation.
func (simplePKI *SimplePKI) GeneratePEM(x509Object any) ([]byte, error) {
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

	var innerIdx int
	if derBytes[1] == 0x82 {
		innerIdx = 4
	} else if derBytes[1] == 0x81 {
		innerIdx = 3
	} else {
		innerIdx = 2
	}

	detectedType := "UNKNOWN"

	if derBytes[innerIdx] == 0x30 {
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
				if layer3Idx+2 < len(derBytes) && derBytes[layer3Idx+1] == 0x01 && derBytes[layer3Idx+2] == 0x00 {
					detectedType = "CERTIFICATE REQUEST"
				} else {
					detectedType = "CERTIFICATE"
				}
			case 0xA0:
				detectedType = "CERTIFICATE"
			case 0x30:
				detectedType = "PUBLIC KEY"
			default:
				detectedType = "PUBLIC KEY"
			}
		}
	} else if derBytes[innerIdx] == 0x02 {
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

// GetTLSConfig returns a standard Go tls.Config.
// If no external certificate was set via a CA signing operation, it automatically self-signs.
func (simplePKI *SimplePKI) GetTLSConfig() (*tls.Config, error) {
	var derBytes []byte
	if len(simplePKI.rawCertDER) == 0 { // cache miss for certificate. generate self-signed cert now
		csr, err := simplePKI.GenerateCertificateSigningRequest(CSROptions{
			CommonName:  _COMMONNAME,
			DNSNames:    []string{_COMMONNAME, "localhost"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate automatic fallback CSR: %w", err)
		}

		fallbackCert, err := simplePKI.SignCertificate(csr, CertificateOptions{NotAfterDays: 365}, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to auto self-sign fallback cert: %w", err)
		}
		derBytes = fallbackCert
	} else {
		derBytes = simplePKI.rawCertDER
	}

	keyPEMblock, err := simplePKI.GeneratePEM(simplePKI.privateKey)
	if err != nil {
		return nil, err
	}
	certPEMblock, err := simplePKI.GeneratePEM(derBytes)
	if err != nil {
		return nil, err
	}
	if tlskeypair, err := tls.X509KeyPair(certPEMblock, keyPEMblock); err != nil {
		return nil, fmt.Errorf("failed parsing PEM pairs to tls.X509KeyPair: %w", err)
	} else {
		config := tls.Config{
			Certificates: []tls.Certificate{tlskeypair},
		}
		return &config, nil
	}
}
