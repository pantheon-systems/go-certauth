package certauth

import (
	"fmt"

	"github.com/julienschmidt/httprouter"
)

// ContextKey and ContextValue are type aliases to make the code a bit more readable.
type ContextKey interface{}
type ContextValue interface{}

// AuthorizationChecker provides an interface for checking request authorization programatically.
// The CheckAuthorization* methods will be called upon a request to verify that the provided client
// is authorized to access the requested resource.
// If authorization is allowed, the AuthorizationChecker should return a nil error value.
// If authorization is denied, the AuthorizationChecker should return an error value with some
// description of why the request is being denied.
// If the request is allowed, the AuthorizationChecker may return a map of key/value pairs.
// These key/value pairs are added to the request's context using `context.WithValue` by the
// middleware. Downstream applications can then use these values if desired.
// See the methods for a description of which Allow* method is chosen depending on the
// request.
type AuthorizationChecker interface {
	// CheckAuthorization is called for requests which do not use the `httprouter` framework.
	// `clientOU` and `clientCN` are set to the values determined from the x509 client certificate.
	CheckAuthorization(clientOU []string, clientCN string) (map[ContextKey]ContextValue, error)

	// CheckAuthorizationWithParams is called for requests which use the `httprouter` framework.
	// This allows the authorization behavior to respond to the resource that's being requested.
	CheckAuthorizationWithParams(
		clientOU []string, clientCN string, ps httprouter.Params,
	) (map[ContextKey]ContextValue, error)
}

// AllowOUsandCNs is a convenience function which produces an AuthorizationChecker from a list
// of allowed OUs and CNs. Requests are allowed if one of their OUs is contained in `allowedOUs`
// and their CN is contained in `allowedCNs`.
// Either of `allowedOUs` or `allowedCNs` is permitted to be nil, which disables checking that
// field.
func AllowOUsandCNs(allowedOUs, allowedCNs []string) AuthorizationChecker {
	return AllowSpecificOUandCNs{OUs: allowedOUs, CNs: allowedCNs}
}

// AllowSpecificOUandCNs is an AuthorizationChecker which allows access to
// resources for the specific Organizational Units and common names.
// If any of the client's OUs match (i.e. `==`) any of the server's allowed OUs, *and*
// the client's CN matches (i.e. `==`) one of the server's allowed CNs, the request
// is allowed.
// If `OUs` is empty or nil, the client's OU is ignored, and only the CN is used to determine
// authorization.
// If `CNs` is empty or nil, the client's CN is ignored, and only the OU is used to determine
// authorization.
// If both `OUs` and `CNs` are empty or nil, all requests are allowed.
// Site resources are not considered specially. CheckAuthorizationWithParams has exactly the same
// behavior as CheckAuthorization (i.e. the parameters are ignored).
type AllowSpecificOUandCNs struct {
	OUs []string
	CNs []string
}

func (allow AllowSpecificOUandCNs) CheckAuthorization(
	clientOU []string, clientCN string,
) (map[ContextKey]ContextValue, error) {
	results := make(map[ContextKey]ContextValue)

	if allow.OUs != nil && len(allow.OUs) > 0 {
		if err := allowedOU(allow.OUs, clientOU); err != nil {
			return nil, err
		}
		results[HasAuthorizedOU] = clientOU
	}
	if allow.CNs != nil && len(allow.CNs) > 0 {
		if err := allowedCN(allow.CNs, clientCN); err != nil {
			return nil, err
		}
		results[HasAuthorizedCN] = clientCN
	}
	return results, nil
}

func (allow AllowSpecificOUandCNs) CheckAuthorizationWithParams(
	clientOU []string, clientCN string, ps httprouter.Params,
) (map[ContextKey]ContextValue, error) {
	// URI parameters are not handled separately. Fall back to the behavior
	// of CheckAuthorization
	return allow.CheckAuthorization(clientOU, clientCN)
}

//
// Unexported helper functions below
//

func allowedCN(allowedCNs []string, clientCN string) error {
	for _, cn := range allowedCNs {
		if cn == clientCN {
			return nil
		}
	}
	return fmt.Errorf(
		"cert failed CN validation for %v, Allowed: %v", clientCN, allowedCNs)
}

func allowedOU(allowedOUs []string, clientOUs []string) error {
	var failed []string

	for _, ou := range allowedOUs {
		for _, clientOU := range clientOUs {
			if ou == clientOU {
				return nil
			}
			failed = append(failed, clientOU)
		}
	}
	return fmt.Errorf(
		"cert failed OU validation for %v, Allowed: %v", failed, allowedOUs)
}
