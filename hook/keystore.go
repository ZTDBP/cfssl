package hook

import (
	"crypto"
	"crypto/x509"
)

// KeyStore 用于动态获取 CA 证书
type KeyStore interface {
	GetPrivKey() (crypto.Signer, error)
	GetCert() (*x509.Certificate, error)
	GetTrustCerts() ([]*x509.Certificate, error)
}

// KeyStorer 全局实例, 用于调用关系解耦, 由 CapitaliZone 注入
// ** 未注入会导致 panic **
var KeyStorer KeyStore