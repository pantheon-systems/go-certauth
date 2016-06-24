package certauth

import (
	"crypto/x509"
	"errors"
	"fmt"
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

// Options is the configuration for a Auth handler
type Options struct {
	// AllowedOUs is an exact string match against the Client Certs OU's
	AllowedOUs []string

	// AllowedCNs is an exact string match against the Client Certs CN
	AllowedCNs []string

	// Populate Headers with auth info
	SetReqHeaders bool

	// Default handler
	AuthErrorHandler http.HandlerFunc
}

type Auth struct {
	opt            Options
	authErrHandler http.Handler
}

// NewAuth returns an auth
func NewAuth(opts ...Options) *Auth {
	o := Options{}
	if len(opts) != 0 {
		o = opts[0]
	}

	h := defaultAuthErrorHandler
	if o.AuthErrorHandler != nil {
		h = o.AuthErrorHandler
	}

	return &Auth{
		opt:            o,
		authErrHandler: http.HandlerFunc(h),
	}
}

func defaultAuthErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Authentication Failed", http.StatusForbidden)
}

// Handler implements the http.HandlerFunc for integration with the standard net/http lib.
func (a *Auth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		err := a.Process(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Process is the main Entrypoint
func (a *Auth) Process(w http.ResponseWriter, r *http.Request) error {
	// ensure we can process this request
	if r.TLS == nil || r.TLS.VerifiedChains == nil {
		return errors.New("no cert chain detected")
	}

	// Validate OU
	if len(a.opt.AllowedOUs) > 0 {
		err := a.ValidateOU(r.TLS.VerifiedChains)
		if err != nil {
			a.authErrHandler.ServeHTTP(w, r)
			return err
		}
	}

	// Validate CN
	if len(a.opt.AllowedCNs) > 0 {
		err := a.ValidateCN(r.TLS.VerifiedChains)
		if err != nil {
			a.authErrHandler.ServeHTTP(w, r)
			return err
		}
	}

	// Set Headers
	return nil
}

// ValidateCN is a httprouter handler that will check the CN, and raise a 403 if the CN doesn't match client cert
func (a *Auth) ValidateCN(verifiedChains [][]*x509.Certificate) error {
	var failed []string

	for _, chain := range verifiedChains {
		for _, c := range chain {
			for _, cn := range a.opt.AllowedCNs {
				if cn == c.Subject.CommonName {
					return nil
				}
				failed = append(failed, c.Subject.CommonName)
			}
		}
	}
	return fmt.Errorf("cert failed CN validation for %v, Allowed: %v", failed, a.opt.AllowedCNs)
}

// ValidateCN is a httprouter handler that will check the CN, and raise a 403 if the CN doesn't match client cert
func (a *Auth) ValidateOU(verifiedChains [][]*x509.Certificate) error {
	var failed []string

	for _, chain := range verifiedChains {
		for _, c := range chain {
			for _, ou := range a.opt.AllowedOUs {
				for _, clientOU := range c.Subject.OrganizationalUnit {
					if ou == clientOU {
						return nil
					}
					failed = append(failed, clientOU)
				}
			}
		}
	}
	return fmt.Errorf("cert failed OU validation for %v, Allowed: %v", failed, a.opt.AllowedCNs)
}
