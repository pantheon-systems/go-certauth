package pantheon_auth

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"

	"github.com/pantheon-systems/go-certauth"
)

// These shenanigans are here to ensure we have strings on our context keys, and they are unique to our package
type contextKey string

func (c contextKey) String() string {
	return "pantheon context " + string(c)
}

const (
	// PantheonSite is used as the request context key identifying the client's Site (if present)
	PantheonSite = contextKey("Pantheon Site")

	//PantheonEnv is used as the request context key identifying the client's environment
	// (if present)
	PantheonEnv = contextKey("Pantheon Env")
)

// Helper function which produces AuthorizationCheckers suitable for use in Pantheon HTTP servers.
// This function accepts three lists which determine which clients pass authorization checks
// and produces 2 AuthorizationCheckers to implement these checks.
// `allowedOUs` and `allowedCNs` determine which clients will be allowed to pass authorization
// checks. Clients with an OU within `siteOUs` will be subject to an additional check for valid
// site authorization. See below for a description of how site authorization works.
// Requests are allowed if they pass `allowedOUs`, `allowedCNs` *and* site authorization
// (if applicable). Note that this means `siteOUs` should be a subset of `allowedOUs` otherwise
// site authorization checks will always fail.
// See also the documentation for AllowSpecificOUandCNs for more details on the behavior or
// `allowedOUs` and `allowedCNs`.
//
// Site authorization checks are intended to protect resources belonging to one site (i.e. with a
// `site` URI parameter) from being accessed by requests from other sites.
// For example: if site A makes a request for information belonging to site B, that request should
// fail the site authorization check.
//
// The way this works hinges on the use of URI parameters with the `httprouter` framework.
// Essentially, the server can define certain URIs as being site-specific by adding a `site` URI
// parameter. The site authorization check then compares the `site` URI parameter with the `site`
// determined from the client certificate's CommonName. If they match, then the request is allowed.
//
// However, this check should only be run for some clients, particularly client's that have
// authenticated as a site (rather than, for example, a backend service). To conditionally apply
// this check, the `siteOUs` parameter allows you to specify which Organizational Units this site
// authorization check should be run for.
//
// In order for site authorization checks to be run, a few things must be true:
// 1. The server must be using the `httprouter` framework.
// 2. The server must define the `site` URI parameter in the URI path.
// 3. The request must be performed against one of the URIs with the `site` parameter.
// 4. At least one of the request's OUs must be present in the `siteOUs` option of `PantheonSiteAuth`
// If all of these conditions are true, then an additional check is performed.
// The workflow for this check is:
// 1. Parse the request x509's CommonName to obtain the site ID.
// 2. Obtain the site ID from the URI parameters.
// 3. Ensure the site ID from the CommonName and site ID from the URI parameters match.
func PantheonSiteAuth(allowedOUs, allowedCNs, siteOUs []string) []certauth.AuthorizationChecker {
	return []certauth.AuthorizationChecker{
		certauth.AllowOUsandCNs(allowedOUs, allowedCNs),
		PantheonSiteAuthChecker{siteOUs},
	}
}

// PantheonSiteAuth is an instance of AuthorizationChecker which performs pantheon-specific
// site authorization checks. See documentation for PantheonSiteAuth for details.
type PantheonSiteAuthChecker struct {
	SiteOUs []string
}

func (check PantheonSiteAuthChecker) CheckAuthorization(
	clientOU []string, clientCN string,
) (map[certauth.ContextKey]certauth.ContextValue, error) {
	// Site authorization does not apply to this request because the server
	// is not using the `httprouter` framework.

	// TODO(zeal): Maybe fail here since we expect all pantheon HTTP servers to be using
	//             `httprouter`?
	return nil, nil
}

func (check PantheonSiteAuthChecker) CheckAuthorizationWithParams(
	clientOU []string, clientCN string, ps httprouter.Params,
) (map[certauth.ContextKey]certauth.ContextValue, error) {
	if !checkOUMembership(check.SiteOUs, clientOU) {
		// Site authorization does not apply to this request because
		// the request is not a member of any of the SiteOUs.
		return nil, nil
	}
	uriSite := ps.ByName("site")
	if uriSite == "" {
		// Site authorization does not apply to this request because
		// the request is not for a resource with the `site` URI parameter.
		return nil, nil
	}

	// From here on, we *know* we need to check this request's authorization.

	certSite, certEnv, err := ParseSiteEnvFromCN(clientCN)
	if err != nil {
		// Couldn't parse site/env from CN, so reject the request...
		return nil, err
	}

	if certSite != uriSite {
		return nil, fmt.Errorf(
			"site %q is not authorized to requests for site %q",
			certSite,
			uriSite,
		)
	}

	return prepareSiteContextParams(certSite, certEnv), nil
}

func prepareSiteContextParams(site, env string) map[certauth.ContextKey]certauth.ContextValue {
	return map[certauth.ContextKey]certauth.ContextValue{
		certauth.ContextKey(PantheonSite): certauth.ContextValue(site),
		certauth.ContextKey(PantheonEnv):  certauth.ContextValue(env),
	}
}

// Checks a client's list of OUs against the server's list of OUs and returns true if there
// are any in common.
func checkOUMembership(serverOUs, clientOUs []string) bool {
	for _, sou := range serverOUs {
		for _, cou := range clientOUs {
			if sou == cou {
				return true
			}
		}
	}
	return false
}

// ParseSiteEnvFromCN parses a site id and environment from the provided CN.
// Also validates that the site ID is a valid UUID.
// Returns (site, environment, nil) if the clientCN is valid.
// Returns ("", "", err) if an error occurs.
func ParseSiteEnvFromCN(clientCN string) (string, string, error) {
	// Site CN in format of env.site_uuid.domain
	words := strings.SplitN(clientCN, ".", 3)

	if len(words) != 3 {
		return "", "", fmt.Errorf("unexpected CN format: %q", clientCN)
	}
	_, err := uuid.Parse(words[1])
	if err != nil {
		return "", "", fmt.Errorf("site ID (from CN) is not a valid UUID: %q", words[1])
	}
	return words[1], words[0], nil
}
