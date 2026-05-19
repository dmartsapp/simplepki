# Example usage

## Simple

Generate a CSR with IP for localhost, CN = "farhan" and ON = dmarts.app
```go
package main

import (
	"fmt"
	"net"

	"github.com/dmartsapp/simplepki"
)

func main() {
	spki, _ := simplepki.New(4096)
	csr, _ := spki.GenerateCertificateSigningRequest(simplepki.CSROptions{
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		CommonName:   "farhan",
		Organization: []string{"dmarts.app"},
	})
	csr, _ = spki.GeneratePEM(csr)
	fmt.Println(string(csr))
}
```

### Validation with openssl

```bash
$ openssl req  -in csr -text -noout
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=BD + C=CA + C=UK + C=US, O=dmarts.app, CN=farhan
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:e3:86:0d:82:e6:84:7c:57:50:a6:bb:e8:71:10:
                    97:46:93:03:8a:b1:cc:2d:9b:32:b4:53:f0:d0:3f:
                    c8:f9:b5:b2:1d:bd:16:ad:57:c4:48:0c:d3:d3:bd:
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name:
                    IP Address:127.0.0.1
    Signature Algorithm: sha512WithRSAEncryption
    Signature Value:
        5e:b2:08:24:13:20:90:72:ad:69:3c:31:26:92:98:60:cd:e6:
        de:59:a3:fc:e4:2f:74:b1:1c:08:4d:4c:02:1c:55:e1:5d:7e:
        ...
```
