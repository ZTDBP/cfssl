package roots

import (
	"crypto/x509"
	"github.com/ztalab/cfssl/helpers"
)

func NewSystem(_ map[string]string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	certpool, err := x509.SystemCertPool()
	if err != nil {
		// 返回 nil，否则 panic
		return nil, nil
	}
	for _, pem := range certpool.Subjects() {
		cert, err := helpers.ParseCertificatesPEM(pem)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert...)
	}
	return certs, nil
}
