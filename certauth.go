package certauth

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// These shenanigans are here to ensure we have strings on our context keys, and they are unique to our package
type contextKey string

func (c contextKey) String() string {
	return "certauth context " + string(c)
}

const (
	//HasAuthorizedOU is used as the request context key, adding info about the authorized OU if authorization succeded
	HasAuthorizedOU = contextKey("Has Authorized OU")

	//HasAuthorizedCN is used as the request context key, adding info about the authroized CN if authorization succeeded
	HasAuthorizedCN = contextKey("Has Authorized CN")
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

// Auth is an instance of the middleware
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
		if err := a.Process(w, r); err != nil {
			// if process returned an error request should not continue
			return
		}

		ctx := r.Context()
		if len(a.opt.AllowedOUs) > 0 {
			ctx = context.WithValue(ctx, HasAuthorizedOU, r.TLS.VerifiedChains[0][0].Subject.OrganizationalUnit)
		}

		if len(a.opt.AllowedCNs) > 0 {
			ctx = context.WithValue(ctx, HasAuthorizedCN, r.TLS.VerifiedChains[0][0].Subject.CommonName)
		}

		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RouterHandler implements the httprouter.Handle for integration with github.com/julienschmidt/httprouter
func (a *Auth) RouterHandler(h httprouter.Handle) httprouter.Handle {
	return httprouter.Handle(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		if err := a.Process(w, r); err != nil {
			return
		}

		h(w, r, ps)
	})
}

// ValidateRequest perfomrs verification on the TLS certs and chain
func (a *Auth) ValidateRequest(r *http.Request) error {
	// ensure we can process this request
	if r.TLS == nil || r.TLS.VerifiedChains == nil {
		return errors.New("no cert chain detected")
	}

	// TODO: Figure out if having multiple validated peer leaf certs is possible. For now, only validate
	// one cert, and make sure it matches the first peer certificate
	if r.TLS.PeerCertificates != nil {
		if !bytes.Equal(r.TLS.PeerCertificates[0].Raw, r.TLS.VerifiedChains[0][0].Raw) {
			return errors.New("first peer certificate not first verified chain leaf")
		}
	}

	return nil
}

// Process is the main Entrypoint
func (a *Auth) Process(w http.ResponseWriter, r *http.Request) error {
	if err := a.ValidateRequest(r); err != nil {
		return err
	}

	// Validate OU
	if len(a.opt.AllowedOUs) > 0 {
		err := a.ValidateOU(r.TLS.VerifiedChains[0][0])
		if err != nil {
			a.authErrHandler.ServeHTTP(w, r)
			return err
		}
	}

	// Validate CN
	if len(a.opt.AllowedCNs) > 0 {
		err := a.ValidateCN(r.TLS.VerifiedChains[0][0])
		if err != nil {
			a.authErrHandler.ServeHTTP(w, r)
			return err
		}
	}
	return nil
}

// ValidateCN checks the CN of a verified peer cert and raises a 403 if the CN doesn't match any CN in the AllowedCNs list.
func (a *Auth) ValidateCN(verifiedCert *x509.Certificate) error {
	var failed []string

	for _, cn := range a.opt.AllowedCNs {
		if cn == verifiedCert.Subject.CommonName {
			return nil
		}
		failed = append(failed, verifiedCert.Subject.CommonName)
	}
	return fmt.Errorf("cert failed CN validation for %v, Allowed: %v", failed, a.opt.AllowedCNs)
}

// ValidateOU checks the OU of a verified peer cert and raises 403 if the OU doesn't match any OU in the AllowedOUs list.
func (a *Auth) ValidateOU(verifiedCert *x509.Certificate) error {
	var failed []string

	for _, ou := range a.opt.AllowedOUs {
		for _, clientOU := range verifiedCert.Subject.OrganizationalUnit {
			if ou == clientOU {
				return nil
			}
			failed = append(failed, clientOU)
		}
	}
	return fmt.Errorf("cert failed OU validation for %v, Allowed: %v", failed, a.opt.AllowedOUs)
}
