package certauth

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
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

// **DEPRECATED** use New with AuthOptions instead
// Options is the configuration for a Auth handler
type Options struct {
	// AllowedOUs is an exact string match against the Client Certs OU's
	// This gets injected into AuthorizationCheckers using AllowOUsandCNs.
	AllowedOUs []string

	// AllowedCNs is an exact string match against the Client Certs CN
	// This gets injected into AuthorizationCheckers using AllowOUsandCNs.
	AllowedCNs []string

	// Performs Authorization checks
	// Each check validates that the client is authorized to the requested resource.
	// See documentation for AuthorizationChecker for details on the checks.
	AuthorizationCheckers []AuthorizationChecker

	// Populate Headers with auth info
	SetReqHeaders bool

	// Default handler
	AuthErrorHandler http.HandlerFunc
}

// Auth is an instance of the middleware
type Auth struct {
	opt Options // **DEPRECATED**
	// lists of checkers: auth if any list passes, a list passes if all checkers in the list pass
	checkers     [][]AuthorizationChecker
	setHeaders   bool
	errorHandler http.Handler
}

// AuthOption is a type of function for configuring an Auth
type AuthOption func(*Auth)

// WithCheckers configures an Auth with the given checkers so that the Auth will pass when all the
// checkers in any WithCheckers AuthOption pass.
// eg: New(WithCheckers(A), WithCheckers(B,C)) will pass on `A || (B && C)`
func WithCheckers(checkers ...AuthorizationChecker) AuthOption {
	return func(a *Auth) {
		a.checkers = append(a.checkers, checkers)
	}

}

func WithHeaders() AuthOption {
	return func(a *Auth) {
		a.setHeaders = true
	}
}

func WithErrorHandler(handler http.Handler) AuthOption {
	return func(a *Auth) {
		a.errorHandler = handler
	}

}

func New(opts ...AuthOption) *Auth {
	a := &Auth{
		errorHandler: http.HandlerFunc(defaultAuthErrorHandler),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// **DEPRECATED** use New instead
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

	if len(o.AllowedOUs) > 0 || len(o.AllowedCNs) > 0 {
		o.AuthorizationCheckers = append(
			o.AuthorizationCheckers,
			AllowOUsandCNs(o.AllowedOUs, o.AllowedCNs),
		)
	}

	return &Auth{
		opt:          o,
		errorHandler: http.HandlerFunc(h),
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
		var err error
		if r, err = a.Process(w, r); err != nil {
			// if process returned an error request should not continue
			return
		}

		h.ServeHTTP(w, r)
	})
}

// RouterHandler implements the httprouter.Handle for integration with github.com/julienschmidt/httprouter
func (a *Auth) RouterHandler(h httprouter.Handle) httprouter.Handle {
	return httprouter.Handle(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		var err error
		if r, err = a.ProcessWithParams(w, r, ps); err != nil {
			return
		}

		h(w, r, ps)
	})
}

// Process validates a request and sets context parameters according to the
// configured AuthorizationCheckers.
// Returns an http.Request with additional context values applied, or an error if
// something went wrong.
// In practice, this just calls ProcessWithParams.
func (a *Auth) Process(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	return a.ProcessWithParams(w, r, nil)
}

// ProcessWithParams validates a request and sets context parameters according to the
// configured AuthorizationCheckers.
// Returns an http.Request with additional context values applied, or an error if
// something went wrong.
func (a *Auth) ProcessWithParams(
	w http.ResponseWriter, r *http.Request, ps httprouter.Params,
) (*http.Request, error) {
	if err := a.ValidateRequest(r); err != nil {
		return nil, err
	}

	ctxParams, err := a.CheckAuthorization(r.TLS.VerifiedChains[0][0], ps)
	if err != nil {
		a.errorHandler.ServeHTTP(w, r)
		return nil, err
	}

	if len(ctxParams) == 0 {
		// No need to update the context; just return the one we already have
		return r, nil
	}

	// Prepare a new context with the additional values
	ctx := r.Context()
	for k, v := range ctxParams {
		ctx = context.WithValue(ctx, k, v)
	}

	// Replace the context on the request object
	return r.WithContext(ctx), nil
}

// ValidateRequest performs verification on the TLS certs and chain
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

// CheckAuthorization runs each of the AuthorizationCheckers configured for the server
// and returns an error if any of them return False.
// See the documentation for AuthorizationChecker for more details.
func (a *Auth) CheckAuthorization(
	verifiedCert *x509.Certificate, ps httprouter.Params,
) (map[ContextKey]ContextValue, error) {
	ou := verifiedCert.Subject.OrganizationalUnit
	cn := verifiedCert.Subject.CommonName

	ctxParams := make(map[ContextKey]ContextValue)
	var (
		params map[ContextKey]ContextValue
		err    error
	)

	checkers := append([][]AuthorizationChecker{}, a.checkers...)
	if len(a.opt.AuthorizationCheckers) > 0 {
		checkers = append(checkers, a.opt.AuthorizationCheckers)
	}
	for _, cks := range checkers { // trying all the groups of checkers
		for _, ck := range cks { // each checker in a group
			if ps == nil { // not using httprouter
				params, err = ck.CheckAuthorization(ou, cn)
			} else { // using httprouter
				params, err = ck.CheckAuthorizationWithParams(ou, cn, ps)
			}
			if err != nil { // stop trying checkers in this group if one fails
				break
			}
			// Collect the context params from each AuthorizationChecker into one map
			if params != nil {
				for k, v := range params {
					ctxParams[k] = v
				}
			}
		}
		// non-nil when a group doesn't pass, so nil means a group passed, so we're done
		if err == nil {
			break
		}
	}
	return ctxParams, err
}
