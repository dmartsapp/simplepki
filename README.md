# SimplePKI

A lightweight, zero-dependency Go library for managing internal Public Key Infrastructure (PKI). **SimplePKI** abstracts the complexities of the `crypto/x509` package, allowing you to generate keys, create CSRs, and sign certificates with a single line of code.

## Features

* **Automated PEM Encoding**: Includes a built-in ASN.1 sniffer that automatically identifies and wraps raw DER bytes in the correct PEM headers (`CERTIFICATE`, `PRIVATE KEY`, etc.).
* **Flexible Signing**: Supports both self-signed certificates and CA-signed hierarchies.
* **Modern Standards**: Defaults to PKCS#8 for private keys and PKIX for public keys.
* **Zero Dependencies**: Uses only the Go standard library for maximum security and compatibility.

## Installation

```bash
go get [github.com/dmartsapp/simplepki](https://github.com/dmartsapp/simplepki)
