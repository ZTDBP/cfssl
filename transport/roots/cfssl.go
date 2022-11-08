package roots

import (
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/ztalab/cfssl/api/client"
	"github.com/ztalab/cfssl/helpers"
	"github.com/ztalab/cfssl/info"
	"github.com/ztalab/cfssl/log"
)

// This package contains CFSSL integration.

// NewCFSSL produces a new CFSSL root.
func NewCFSSL(metadata map[string]string) ([]*x509.Certificate, error) {
	host, ok := metadata["host"]
	if !ok {
		return nil, errors.New("transport: CFSSL root provider requires a host")
	}

	label := metadata["label"]
	profile := metadata["profile"]
	cert, err := helpers.LoadClientCertificate(metadata["mutual-tls-cert"], metadata["mutual-tls-key"])
	if err != nil {
		return nil, err
	}
	remoteCAs, err := helpers.LoadPEMCertPool(metadata["tls-remote-ca"])
	if err != nil {
		return nil, err
	}

	srv := client.NewServerTLS(host, helpers.CreateTLSConfig(remoteCAs, cert))
	data, err := json.Marshal(info.Req{Label: label, Profile: profile})
	if err != nil {
		return nil, err
	}

	resp, err := srv.Info(data)
	if err != nil {
		log.Errorf("请求 CA Server 错误: %v", err)
		return nil, err
	}

	log.Debugf("CA Server 返回数据: %v", *resp)

	certs, err := helpers.ParseCertificatesPEM([]byte(resp.Certificate))
	if err != nil {
		return nil, err
	}
	for _, rootCertStr := range resp.TrustCertificates {
		rootCert, err := helpers.ParseCertificatePEM([]byte(rootCertStr))
		if err != nil {
			log.Warningf("trust 证书解析失败: %v", err)
			continue
		}
		certs = append(certs, rootCert)
	}

	return certs, nil
}
