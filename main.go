package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	Parser "github.com/mmaFR/ArgumentsAsStruct"
	"io"
	"log"
	"net/http"
	"os"
)

type Args struct {
	ServerCertificatePath string `default:"server.pem" usage:"the certificate path to use to build the certificate chain" alias:"i"`
	CertificateChainPath  string `default:"chain.pem" usage:"the path to use to dump the certificate chain" alias:"o"`
}

func main() {
	var args Args
	Parser.Parse(&args)
	var err error
	var cert *x509.Certificate
	var chain []*x509.Certificate
	if cert, err = LoadCertificateFromFile(args.ServerCertificatePath); err != nil {
		log.Fatal(err)
	}
	if cert.IsCA {
		fmt.Println("ERROR: the certificate provided is a CA certificate, a server certificate is expected")
	}
	if chain, err = BuildCertChain(cert); err != nil {
		log.Fatal(err)
	}
	if err = DumpChain(chain, args.CertificateChainPath); err != nil {
		log.Fatal(err)
	}
}

func LoadCertificateFromFile(certPath string) (*x509.Certificate, error) {
	var err error
	var pemBytes []byte
	if pemBytes, err = os.ReadFile(certPath); err != nil {
		return nil, err
	}
	return ParsePemBytes(pemBytes)
}

func ParsePemBytes(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block.Bytes == nil {
		return nil, errors.New("unable to parse the PEM data")
	}
	return ParseDerBytes(block.Bytes)
}

func ParseDerBytes(derBytes []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(derBytes)
}

func BuildCertChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	var err error
	var chain []*x509.Certificate = make([]*x509.Certificate, 0, 4)
	var ca *x509.Certificate
	chain = append(chain, cert)
	for loop := true; loop; {
		if ca, err = GetIssuerCert(chain[len(chain)-1]); err != nil {
			return nil, err
		}
		chain = append(chain, ca)
		if CaIsRoot(ca) {
			loop = false
		}
	}

	return chain, nil
}

func GetIssuerCert(cert *x509.Certificate) (*x509.Certificate, error) {
	var err error
	var response *http.Response
	var responseBytes []byte
	var issuerCert *x509.Certificate
	//cert.IssuingCertificateURL[0]
	var httpClient http.Client
	if response, err = httpClient.Get(cert.IssuingCertificateURL[0]); err != nil {
		return nil, err
	}
	if responseBytes, err = io.ReadAll(response.Body); err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	if issuerCert, err = ParseDerBytes(responseBytes); err != nil {
		return nil, err
	}

	return issuerCert, nil
}

func CaIsRoot(cert *x509.Certificate) bool {
	return CompareStringSliceContent(cert.Subject.Country, cert.Issuer.Country) && CompareStringSliceContent(cert.Subject.Organization, cert.Issuer.Organization) && cert.Subject.CommonName == cert.Issuer.CommonName
}

func CompareStringSliceContent(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, content := range a {
		if b[idx] != content {
			return false
		}
	}
	return true
}

func EncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func DumpChain(chain []*x509.Certificate, path string) error {
	var err error
	var fd *os.File
	var chainBytes []byte = make([]byte, 0)
	for _, c := range chain {
		chainBytes = append(chainBytes, EncodeCert(c)...)
	}
	if fd, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_SYNC, 0640); err != nil {
		return err
	}
	defer fd.Close()
	if _, err = fd.Write(chainBytes); err != nil {
		return err
	}
	return nil
}
