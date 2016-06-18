package certauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
)

// TODO:(jnelson) Maybe a standardValidation method for our stuff? Thu May 14 18:41:41 2015
// Current Auth methods:
//   see panthon/auth.py
//    - /:endpoint/bindings
//      - Standard OU validation (titan)
//    	- OU:endpoint & CN:matches endpoint parram.
//
//    - /bindings/:id
//      - Standard OU validation (titan)
//    	- OU:endpoint & CN:matches endpoint parram. (ygg knows what EP has that ID)
//      - OU:site & CN:matches SiteID

// TLSAuther is the interface for Validating HTTP handlers. Useful for dep injection when testing
type TLSAuther interface {
	ServHTTP(ResponseWriter, Request)
	Validate(route http.Handler)
	Authorized() bool
}

// CNAuth implements the TLSAuther Interface validating CN
type CNAuth struct {
	allowedCN []string
}

// OUAuth implements the TLSAuther Interface Validating OU
type OUAuth struct {
	allowedOU []string
}

// ServerConfig is the configuration you use to create a TLSServer
type ServerConfig struct {
	CertPool    *x509.CertPool
	BindAddress string
	Port        int
	Router      http.Handler
}

// NewCNAuth returns an auther that can be used to to validate CN
func NewCNAuth(auth string) TLSAuther {
	return CNAuth{allowedCN: []string{auth}}
}

// Validate Implement Auther Interface on CNAuth by validating the CN against the configured list. And
// Either running the route or returning 403
func (a CNAuth) Validate(route http.Handler) {

}

func (a CNAuth) Authorized() bool {
}

// NewTLSServer sets up a Pantheon(TM) type of tls server that Requires and Verifies peer cert
func NewTLSServer(config Config) *http.Server {
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

func (a CNAuth) validate(verifiedChains [][]*x509.Certificate) bool {
	for _, chain := range verifiedChains {
		for _, c := range chain {
			for _, cn := range a.allowedCN {
				if cn == c.Subject.CommonName {
					return true
				}
			}
		}
	}
	return false
}

// ValidateCN is a httprouter handler that will check the CN, and raise a 403 if the CN doesn't match client cert
// TODO:(jnelson) this should probably take  a []string or some other struct maybe to validate multiple CN values Wed May 13 03:02:49 2015
// TODO:(jnelson) there should also be a way to make the CN/OU validators share more  Wed May 13 03:02:39 2015
func (a DefaultAuth) ValidateCN(cn string, route http.Handler) http.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		var failed []string

		for _, chain := range r.TLS.VerifiedChains {
			for _, c := range chain {
				if cn == c.Subject.CommonName {
					route.ServeHTTP(w, r)
					return
				}
				failed = append(failed, cn)
			}
			log.Printf("cert failed CN validation %+v no match for %s", failed, cn)
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
}

// ValidateCN is a httprouter handler that will check the OU, and raise a 403 if the OU doesn't match client cert
func (a DefaultAuth) ValidateOU(ou string, route http.Handler) http.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		var failed []string

		for _, chain := range r.TLS.VerifiedChains {
			for _, c := range chain {
				for _, o := range c.Subject.OrganizationalUnit {
					if o == ou {
						// TODO:(jnelson) set a verified headder Wed May 13 03:04:13 2015
						// TODO:(jnelson) better request logging Fri May 15 14:39:30 2015
						route(w, r)
						return
					}
					failed = append(failed, o)
				}
			}
			log.Printf("cert failed OU validation %+v no match for %s", failed, ou)
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
}
