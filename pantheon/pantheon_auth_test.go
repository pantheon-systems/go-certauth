package pantheon_auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/pantheon-systems/go-certauth"
	pantheon_auth "github.com/pantheon-systems/go-certauth/pantheon"
)

func expect(t *testing.T, actual interface{}, expected interface{}) {
	t.Helper()
	if actual != expected {
		t.Errorf("Expected [%v] (type %T) - Got [%v] (type %T)", expected, expected, actual, actual)
	}
}

func expectErr(t *testing.T, actual error, expected error) {
	t.Helper()
	if (actual == nil && expected == nil) || (actual != nil && expected != nil && actual.Error() == expected.Error()) {
		return
	}
	t.Errorf("Expected error [%v] - Got error [%v]", expected, actual)
}

type fakeCertData struct {
	ou []string
	cn string
}

// fakeCertChain will turn a []fakeCertData into a [][]*x509.Certificate which is the
// type found in the `http.Request.TLS.VerifiedChains` attribute.
func fakeCertChain(certChainData ...fakeCertData) [][]*x509.Certificate {
	chain := []*x509.Certificate{}
	for _, certData := range certChainData {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string(certData.ou),
				CommonName:         string(certData.cn),
			},
		}
		chain = append(chain, cert)
	}
	return [][]*x509.Certificate{chain}
}

// helper function to create a single test certificate with one OU and the given CN
func makeFakeCert(ou, cn string) [][]*x509.Certificate {
	return fakeCertChain(
		fakeCertData{[]string{ou}, cn},
	)
}

func TestSiteAuthorization(t *testing.T) {
	// This test sets up a httprouter server with an endpoint specifically made to test site
	// authorization.
	auth := certauth.NewAuth(certauth.Options{
		AuthorizationCheckers: pantheon_auth.PantheonSiteAuth(
			// Only allow OUs `site` and `engineering`
			[]string{"site", "engineering"},
			// If the OU is `site` do a site-authorization check
			[]string{"site"},
			// Allow the `self` site
			true,
		),
	})

	siteResource := "/site_test/:site"
	nonSiteResource := "/not_site_test/:nosite"

	rtr := httprouter.New()
	// If authorization passes, the handler fetches the URI's site and
	// certificate's site and writes them back to the client via the http
	// response body so the test can assert on the content.
	rtr.GET(siteResource, auth.RouterHandler(httprouter.Handle(
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			uriSite := ps.ByName("site")
			certSite, ok := r.Context().Value(pantheon_auth.PantheonSite).(string)
			if !ok {
				certSite = "<none>"
			}
			fmt.Fprintf(w, "%s,%s", certSite, uriSite)
		},
	)))
	// This resource does not run site authorization checks because it's URI
	// parameter is not `site`
	rtr.GET(nonSiteResource, auth.RouterHandler(httprouter.Handle(
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			uriSite := ps.ByName("nosite")
			certSite, ok := r.Context().Value(pantheon_auth.PantheonSite).(string)
			if !ok {
				certSite = "<none>"
			}
			fmt.Fprintf(w, "%s,%s", certSite, uriSite)
		},
	)))

	selfurl := "https://foo.bar" + strings.ReplaceAll(siteResource, ":site", "self")
	site1 := "00c66762-d8ac-450b-b368-459c5d4f6aab"
	site1url := "https://foo.bar" + strings.ReplaceAll(siteResource, ":site", site1)
	nsite1url := "https://foo.bar" + strings.ReplaceAll(nonSiteResource, ":nosite", site1)
	site2 := "1fab8f7f-b5cc-411d-abed-7432dd62af60"
	site2url := "https://foo.bar" + strings.ReplaceAll(siteResource, ":site", site2)
	nsite2url := "https://foo.bar" + strings.ReplaceAll(nonSiteResource, ":nosite", site2)

	// slices cannot be key indices, so we create this lookup table so we can use a string
	// as the key index in `tests` below and lookup the cert for that test case later.
	clientCerts := map[string][][]*x509.Certificate{
		"admin": makeFakeCert("engineering", "admin@foo.com"),
		"site1": makeFakeCert("site", fmt.Sprintf("dev.%s.foo.com", site1)),
		"site2": makeFakeCert("site", fmt.Sprintf("dev.%s.foo.com", site2)),
	}

	type expectedResponse struct {
		expCode int
		expBody string
	}

	// This is a map from clients to urls to expected responses...
	// If this client sends a request to this URL, what should the response be?
	testCases := map[string]map[string]expectedResponse{
		// admin can send responses to every url
		// and should have a cert site of `<none>` (see handler above)
		"admin": {
			site1url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site1),
			},
			site2url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site2),
			},
			selfurl: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", "self"),
			},
			nsite1url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site1),
			},
			nsite2url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site2),
			},
		},
		"site1": {
			site1url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("%s,%s", site1, site1),
			},
			site2url: {
				expCode: http.StatusForbidden,
				expBody: "Authentication Failed",
			},
			selfurl: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("%s,%s", site1, "self"),
			},
			nsite1url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site1),
			},
			nsite2url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site2),
			},
		},
		"site2": {
			site1url: {
				expCode: http.StatusForbidden,
				expBody: "Authentication Failed",
			},
			site2url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("%s,%s", site2, site2),
			},
			selfurl: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("%s,%s", site2, "self"),
			},
			nsite1url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site1),
			},
			nsite2url: {
				expCode: http.StatusOK,
				expBody: fmt.Sprintf("<none>,%s", site2),
			},
		},
	}
	for clientName, ctc := range testCases {
		cert := clientCerts[clientName]
		for url, tc := range ctc {
			t.Run(fmt.Sprintf("%s=>%s", clientName, url), func(t2 *testing.T) {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", url, nil)
				req.TLS = &tls.ConnectionState{}
				req.TLS.VerifiedChains = cert

				rtr.ServeHTTP(w, req)
				expect(t2, w.Code, tc.expCode)
				expect(t2, strings.TrimSpace(w.Body.String()), strings.TrimSpace(tc.expBody))
			})
		}
	}

}

func TestParsesCNProperly(t *testing.T) {
	tests := []struct {
		InputCN      string
		ExpectedSite string
		ExpectedEnv  string
		ExpectedErr  error
	}{
		{
			"dev.de7ad059-19dd-4e45-9095-ef7507d8195b.pantheon.com",
			"de7ad059-19dd-4e45-9095-ef7507d8195b",
			"dev",
			nil,
		},
		{
			"foobar.9eb5ca28-09be-45b9-8068-7ed6af62fcad.some.website.edu",
			"9eb5ca28-09be-45b9-8068-7ed6af62fcad",
			"foobar",
			nil,
		},
		{
			"I_AM_A_CN",
			"",
			"",
			fmt.Errorf(`unexpected CN format: "I_AM_A_CN"`),
		},
		{
			"dev.myspecialsite1.pantheon.com",
			"",
			"",
			fmt.Errorf(`site ID (from CN) is not a valid UUID: "myspecialsite1"`),
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("CN %s", tc.InputCN), func(t2 *testing.T) {
			actualSite, actualEnv, actualErr := pantheon_auth.ParseSiteEnvFromCN(tc.InputCN)

			expectErr(t2, actualErr, tc.ExpectedErr)
			expect(t2, actualSite, tc.ExpectedSite)
			expect(t2, actualEnv, tc.ExpectedEnv)
		})
	}
}
