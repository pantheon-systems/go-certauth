package certauth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/pantheon-systems/go-certauth"
)

func expect(t *testing.T, a interface{}, b interface{}) {
	t.Helper()
	if a != b {
		t.Errorf("Expected [%v] (type %T) - Got [%v] (type %T)", b, b, a, a)
	}
}

func expectErr(t *testing.T, actual error, expected error) {
	t.Helper()
	if (actual == nil && expected == nil) || (actual != nil && expected != nil && actual.Error() == expected.Error()) {
		return
	}
	t.Errorf("Expected error [%v] - Got error [%v]", expected, actual)
}

// Helper functions for building OU and CN validation errors
func mkOUErr(clientOUs, serverOUs string) error {
	return fmt.Errorf("cert failed OU validation for [%s], allowed: [%s]", clientOUs, serverOUs)
}
func mkCNErr(clientCN, serverCNs string) error {
	return fmt.Errorf(`cert failed CN validation for "%s", allowed: [%s]`, clientCN, serverCNs)
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

func TestDirectlyValidateOU(t *testing.T) {
	// Tests that OU validation works as expected
	// This is similar to TestAuthValidateOU in authorization_test.go
	// but operates one level up the stack.
	tests := []struct {
		Name        string
		AllowedOUs  []string
		ActualOUs   []string
		ExpectedErr error
	}{
		{"MatchingOU", []string{"endpoint"}, []string{"endpoint"}, nil},
		{"MismatchOU", []string{"endpoint"}, []string{"site"}, mkOUErr("site", "endpoint")},
		{"NilOU", []string{"endpoint"}, nil, mkOUErr("", "endpoint")},
		{"EmptyStringOU", []string{"endpoint"}, []string{""}, mkOUErr("", "endpoint")},
		{
			"OUList1",
			[]string{"endpoint", "titan"},
			[]string{"site"},
			mkOUErr("site", "endpoint titan"),
		},
		{"OUList2", []string{"endpoint", "titan"}, []string{"titan"}, nil},
		{"OUList3", []string{"endpoint", "titan"}, []string{"endpoint"}, nil},
	}

	for _, tc := range tests {
		t.Run(tc.Name+"-legacy", func(t2 *testing.T) {
			cert := fakeCertChain(
				fakeCertData{tc.ActualOUs, ""},
			)
			auth := certauth.NewAuth(certauth.Options{
				AllowedOUs: tc.AllowedOUs,
			})
			_, err := auth.CheckAuthorization(cert[0][0], nil)

			expectErr(t, err, tc.ExpectedErr)
		})
		t.Run(tc.Name, func(t2 *testing.T) {
			cert := fakeCertChain(
				fakeCertData{tc.ActualOUs, ""},
			)
			auth := certauth.New(
				certauth.WithCheckers(
					certauth.AllowOUsandCNs(tc.AllowedOUs, []string{}),
					certauth.AllowOUsandCNs(
						[]string{"non-matching-ou"}, []string{"non-matching-cn"},
					),
				),
				certauth.WithCheckers(
					certauth.AllowOUsandCNs(tc.AllowedOUs, []string{}),
					certauth.AllowOUsandCNs(
						[]string{}, []string{},
					),
				),
			)
			_, err := auth.CheckAuthorization(cert[0][0], nil)

			expectErr(t, err, tc.ExpectedErr)
		})
	}
}

func TestDirectlyValidateCN(t *testing.T) {
	// Tests that CN validation works as expected
	// This is similar to TestAuthValidateCN in authorization_test.go
	// but operates one level up the stack.
	tests := []struct {
		Name        string
		AllowedCNs  []string
		ActualCN    string
		ExpectedErr error
	}{
		{"NilServerCN", nil, "", nil},
		{"EmptyServerCN", []string{}, "", nil},
		{"MatchingCN", []string{"foo.com"}, "foo.com", nil},
		{"MismatchCN", []string{"foo.com"}, "bar.com", mkCNErr("bar.com", "foo.com")},
		{"EmptyClientCN", []string{"foo.com"}, "", mkCNErr("", "foo.com")},
	}

	for _, tc := range tests {
		t.Run(tc.Name+"-legacy", func(t2 *testing.T) {
			cert := fakeCertChain(
				fakeCertData{[]string{""}, tc.ActualCN},
			)
			auth := certauth.NewAuth(certauth.Options{
				AllowedCNs: tc.AllowedCNs,
			})
			_, err := auth.CheckAuthorization(cert[0][0], nil)

			expectErr(t, err, tc.ExpectedErr)
		})
		t.Run(tc.Name, func(t2 *testing.T) {
			cert := fakeCertChain(
				fakeCertData{[]string{""}, tc.ActualCN},
			)
			auth := certauth.New(
				certauth.WithCheckers(
					certauth.AllowOUsandCNs(
						[]string{"non-matching-ou"}, []string{"non-matching-cn"},
					),
					certauth.AllowOUsandCNs([]string{}, tc.AllowedCNs),
				),
				certauth.WithCheckers(
					certauth.AllowOUsandCNs(
						[]string{}, []string{},
					),
					certauth.AllowOUsandCNs([]string{}, tc.AllowedCNs),
				),
			)
			_, err := auth.CheckAuthorization(cert[0][0], nil)

			expectErr(t2, err, tc.ExpectedErr)
		})
	}
}

func makeTestCNHandler(t *testing.T, name string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val, ok := r.Context().Value(certauth.HasAuthorizedCN).(string)
		if !ok {
			t.Fatal("Context did not set context HasAuthorizedCN")
		}
		expect(t, val, name)
		fmt.Fprintf(w, "%s", name)
	})
}

func TestMiddleware(t *testing.T) {
	var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bar"))
	})

	allowedCert := fakeCertChain(
		fakeCertData{[]string{"endpoint"}, "foo.com"},
	)
	failedCert := fakeCertChain(
		fakeCertData{[]string{"site"}, "foo.com"},
		fakeCertData{[]string{"endpoint"}, "foo.com"},
	)

	auth := certauth.NewAuth(certauth.Options{
		AllowedOUs: []string{"endpoint", "titan"},
		AllowedCNs: []string{"foo.com"},
	})

	url := "https://foo.bar/foo"

	// failed auth

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", url, nil)
	req.TLS = &tls.ConnectionState{}
	req.TLS.VerifiedChains = failedCert

	auth.Handler(testHandler).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusForbidden)

	//passed auth
	w = httptest.NewRecorder()
	req.TLS.VerifiedChains = allowedCert
	auth.Handler(testHandler).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusOK)
	expect(t, w.Body.String(), "bar")

	// check that the CN is passed in as context
	w = httptest.NewRecorder()
	// NOTE: that the handler function has more assertions!
	auth.Handler(makeTestCNHandler(t, "foo.com")).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusOK)
	expect(t, w.Body.String(), "foo.com")
}

func TestRouterMiddleware(t *testing.T) {
	allowedCert := fakeCertChain(
		fakeCertData{[]string{"endpoint"}, "foo.com"},
	)
	failedCert := fakeCertChain(
		fakeCertData{[]string{"site"}, "foo.com"},
		fakeCertData{[]string{"endpoint"}, "foo.com"},
	)

	auth := certauth.NewAuth(certauth.Options{
		AuthorizationCheckers: []certauth.AuthorizationChecker{
			certauth.AllowOUsandCNs([]string{"endpoint", "titan"}, []string{"foo.com"}),
		},
	})

	name_param := "lorem"
	url1 := fmt.Sprintf("https://foo.bar/foo/%s/bar", name_param)
	url2 := fmt.Sprintf("https://foo.bar/test/%s/cn", "foo.com")
	rtr := httprouter.New()
	rtr.GET("/foo/:test_param/bar", auth.RouterHandler(httprouter.Handle(
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			fmt.Fprintf(w, "%s", ps.ByName("test_param"))
		},
	)))
	rtr.GET("/test/:test_param/cn", auth.RouterHandler(httprouter.Handle(
		func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			param := ps.ByName("test_param")
			val, ok := r.Context().Value(certauth.HasAuthorizedCN).(string)
			if !ok {
				t.Fatal("Context did not set context HasAuthorizedCN")
			}
			expect(t, val, param)
			fmt.Fprintf(w, "%s", param)
		},
	)))

	// failed auth

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", url1, nil)
	req.TLS = &tls.ConnectionState{}
	req.TLS.VerifiedChains = failedCert

	rtr.ServeHTTP(w, req)
	expect(t, w.Code, http.StatusForbidden)

	//passed auth
	w = httptest.NewRecorder()
	req.TLS.VerifiedChains = allowedCert
	rtr.ServeHTTP(w, req)
	expect(t, w.Code, http.StatusOK)
	expect(t, w.Body.String(), name_param)

	// check that the CN is passed in as context
	w = httptest.NewRecorder()
	req.URL, _ = url.Parse(url2)
	// NOTE: the handler has assertions for the checks
	rtr.ServeHTTP(w, req)
	expect(t, w.Code, http.StatusOK)
	expect(t, w.Body.String(), "foo.com")
}
