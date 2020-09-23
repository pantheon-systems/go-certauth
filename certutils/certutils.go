// +build go1.8

package certutils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// TLSConfigLevel declares a TLS configuration level returned by the NewTLSConfig func
type TLSConfigLevel int

// Based on https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
// and the Mozilla TLS recommendations: https://wiki.mozilla.org/Security/Server_Side_TLS
const (
	TLSConfigDefault TLSConfigLevel = iota
	TLSConfigIntermediate
	TLSConfigModern
)

// NewTLSConfig returns a *tls.Config that is pre-configured to match (roughly)
// the Mozilla recommended TLS specification. Different levels of security -vs- compatbility
// can be specified via the 'level' var.
//
// Based on: https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
// Last updated: 2017-01-11
func NewTLSConfig(level TLSConfigLevel) *tls.Config {
	// TLSConfigDefault - golang's default
	c := &tls.Config{}

	switch level {
	case TLSConfigIntermediate:
		// Causes servers to use Go's default ciphersuite preferences, which are tuned to avoid attacks. Does nothing on clients.
		c.PreferServerCipherSuites = true
		// Only use curves which have assembly implementations
		c.CurvePreferences = []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		}
	case TLSConfigModern:
		// Modern compat sets TLS_1.2 minimum version and a set of ciphers that support PFS
		c.MinVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
	}
	return c
}

// TLSServerConfig is the configuration you use to create a TLSServer
type TLSServerConfig struct {
	CertPool       *x509.CertPool
	BindAddress    string
	Port           int
	Router         http.Handler
	TLSConfigLevel TLSConfigLevel
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// NewTLSServer sets up a Pantheon(TM) type of tls server that Requires and Verifies peer cert
func NewTLSServer(config TLSServerConfig) *http.Server {
	// Setup our TLS config
	tlsConfig := NewTLSConfig(config.TLSConfigLevel)

	// By default this server will require client MTLS certs and verify cert validity against the config.CertPool CA bundle
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = config.CertPool

	if config.GetCertificate != nil {
		tlsConfig.GetCertificate = config.GetCertificate
	}

	// Setup client authentication
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second, // Go 1.8 only
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second, // Go 1.8 only
		TLSConfig:         tlsConfig,
		Addr:              fmt.Sprintf("%s:%d", config.BindAddress, config.Port),
		Handler:           config.Router,
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
