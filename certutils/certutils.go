package certutils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

// TLSServerConfig is the configuration you use to create a TLSServer
type TLSServerConfig struct {
	CertPool    *x509.CertPool
	BindAddress string
	Port        int
	Router      http.Handler
}

// NewTLSServer sets up a Pantheon(TM) type of tls server that Requires and Verifies peer cert
func NewTLSServer(config TLSServerConfig) *http.Server {
	// Setup client authentication
	server := &http.Server{
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  config.CertPool,
		},
		Addr:    fmt.Sprintf("%s:%d", config.BindAddress, config.Port),
		Handler: config.Router,
	}
	server.TLSConfig.BuildNameToCertificate()
	return server
}

// LoadKeyCertFiles is a helper function for loading keypairs. it takes the key
// and cert file paths as strings and returns you a proper tls.Certificate
func LoadKeyCertFiles(keyFile, certFile string) (tls.Certificate, error) {
	// validate the server keypair
	cert, err := tls.LoadX509KeyPair(
		certFile,
		keyFile,
	)
	if err != nil {
		return cert, fmt.Errorf("could not load TLS key pair: %s", err.Error())
	}

	return cert, nil
}

// LoadCACertFile reads in a CA cert file that may contain multiple certs
// and gives  you back a proper x509.CertPool for your fun and proffit
func LoadCACertFile(cert string) (*x509.CertPool, error) {
	// validate caCert, and setup certpool
	ca, err := ioutil.ReadFile(cert)
	if err != nil {
		return nil, fmt.Errorf("could not load CA Certificate: %s ", err.Error())
	}

	certPool := x509.NewCertPool()
	if err := certPool.AppendCertsFromPEM(ca); !err {
		return nil, errors.New("could not append CA Certificate to CertPool")
	}

	return certPool, nil
}
