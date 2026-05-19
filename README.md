# SimplePKI

`simplepki` is a lightweight, zero-dependency Go library designed to streamline the programmatic generation of RSA keys, X.509 Certificate Signing Requests (CSRs), and signed Certificates (CRTs). It provides native state-caching and an automated self-signed fallback implementation to instantly yield Go-compliant `tls.Config` structures for HTTPS or secure DTLS workloads.

## Features

- **Extensible CSR Definitions**: Granular control over Subjects, Domain Names, and IP SANs.
- **Robust Certificate Issuance**: Simple abstraction for self-signed development tokens or structured, hierarchical Certificate Authority chains.
- **Dynamic Type Detection**: Built-in ASN.1 structural analyzer to safely wrap raw DER arrays into standard PEM memory strings.
- **State-Aware TLS Provisioning**: Fast caching layer that intercepts configuration setups and auto-provisions structural keys when explicitly declared certificates are missing.

---

## Installation

Add the module to your Go workspace:

```bash
go get [github.com/dmartsapp/simplepki](https://github.com/dmartsapp/simplepki)
```

## Core Usage: Generating a CSR
The following example demonstrates how to spin up a 4096-bit cryptographic instance, request explicit Subject claims containing IP SAN definitions, and capture the output as a valid PEM block.

### Example Code (cmd/example/main.go)
```go
package main

import (
	"fmt"
	"net"

	"[github.com/dmartsapp/simplepki](https://github.com/dmartsapp/simplepki)"
)

func main() {
	// Initialize a new 4096-bit RSA PKI workspace
	spki, _ := simplepki.New(4096)

	// Build a structured request with advanced Subject/SAN overrides
	csrDER, _ := spki.GenerateCertificateSigningRequest(simplepki.CSROptions{
		CommonName:   "farhan",
		Organization: []string{"dmarts.app"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	})

	// Wrap the raw ASN.1 DER sequence into a human-readable PEM block string
	csrPEM, _ := spki.GeneratePEM(csrDER)
	fmt.Println(string(csrPEM))
}
```

### Verifying Outputs with OpenSSL
When you pipe the output of your Go application into a file, it generates a standardized PKCS#10 structure. Because a CSR is an identity request and not a finalized certificate, use the openssl req utility instead of openssl x509 to analyze the payload structural tokens.

#### Step 1: Run and Pipe Output
```bash
go run cmd/example/main.go > csr
```
#### Step 2: Inspect the Request Properties
```bash
openssl req -in csr -text -noout
```
#### Step 1: Expected output
```text
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=BD + C=CA + C=UK + C=US, O=dmarts.app, CN=farhan
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:e3:86:0d:82:e6:84:7c:57:50:a6:bb:e8:71:10:
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    IP Address:127.0.0.1
    Signature Algorithm: sha512WithRSAEncryption
    Signature Value:
        5e:b2:08:24:13:20:90:72:ad:69:3c:31:26:92:98:60:cd:e6:
        ...
```

## API Reference
### Struct Configurations

```text
#### CSROptions
```

Provides configurable properties to dictate identity parameters during request creation:

```go
type CSROptions struct {
	CommonName   string
	Organization []string
	OrgUnit      []string
	Countries    []string
	Locality     []string
	Province     []string
	DNSNames     []string
	IPAddresses  []net.IP
}
```
```text
#### CertificateOptions
```
Configures validation constraints and cryptographic flags during the signing stage:
```go
type CertificateOptions struct {
	NotAfterDays       int
	AsCA               bool
	MaxPathLen         int
	ExtKeyUsages       []x509.ExtKeyUsage
	SignatureAlgorithm x509.SignatureAlgorithm
}
```
#### Methods

```go
New(bits int) (*SimplePKI, error): 
```
Spins up a new instance and provisions an internal key pair.

```go
SetCertificate(derBytes []byte): 
```
Caches a pre-signed certificate inside the internal state loop.

```go
GenerateCertificateSigningRequest(opts CSROptions) ([]byte, error): 
```
Generates a DER-encoded CSR payload.

```go
SignCertificate(csr []byte, opts CertificateOptions, parent *x509.Certificate) ([]byte, error): 
```
Signs a CSR into an operational X.509 certificate.

```go 
GeneratePEM(object any) ([]byte, error): 
```
Parses raw assets dynamically and wraps them in PEM containers.

```go 
GetTLSConfig() (*tls.Config, error): Returns a validated network-ready tls.Config. 
``` 
If no active certificate has been associated, it safely triggers a background self-signing process to ensure secure startup bounds.