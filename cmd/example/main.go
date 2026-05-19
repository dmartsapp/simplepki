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
