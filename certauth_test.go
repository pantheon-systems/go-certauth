package certauth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/pantheon-systems/go-certauth"
)

func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

type fakeCertData struct {
	ou []string
	cn string
}

// fakeCertChain will turn a [][]fakeCertData into a [][]*x509.Certificate which is the
// type found in the `http.Request.TLS.VerifiedChains` attribute.
func fakeCertChain(certs [][]fakeCertData) [][]*x509.Certificate {
	fakeCertChains := [][]*x509.Certificate{}

	for _, certChainData := range certs {
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
		fakeCertChains = append(fakeCertChains, chain)
	}
	return fakeCertChains
}

func TestDirectlyValidateOU(t *testing.T) {
	tests := []struct {
		AllowedOUs     []string
		ActualOUs      []string
		ShouldValidate bool
	}{
		{[]string{"endpoint"}, []string{"endpoint"}, true},
		{[]string{"endpoint"}, []string{"site"}, false},
		{[]string{"endpoint"}, []string{""}, false},
		{[]string{"endpoint", "titan"}, []string{"site"}, false},
		{[]string{"endpoint", "titan"}, []string{"titan"}, true},
	}

	for _, tc := range tests {
		fakeCertData := [][]fakeCertData{
			[]fakeCertData{
				fakeCertData{tc.ActualOUs, ""},
			},
		}
		cert := fakeCertChain(fakeCertData)
		auth := certauth.NewAuth(certauth.Options{
			AllowedOUs: tc.AllowedOUs,
		})
		_, err := auth.CheckAuthorization(cert[0][0], nil)

		if err != nil && tc.ShouldValidate {
			t.Fatalf("Expected AllowedOUs (%v) and ActualOUs (%v) to pass validation, but it failed: err: %s", tc.AllowedOUs, tc.ActualOUs, err)
		}

		if err == nil && !tc.ShouldValidate {
			t.Fatalf("Expected AllowedOUs (%v) and ActualOUs (%v) to failed validation, but it passed.", tc.AllowedOUs, tc.ActualOUs)
		}
	}
}

func TestDirectlyValidateCN(t *testing.T) {
	tests := []struct {
		AllowedCNs     []string
		ActualCN       string
		ShouldValidate bool
	}{
		{[]string{"foo.com"}, "foo.com", true},
		{[]string{"foo.com"}, "bar.com", false},
		{[]string{"foo.com"}, "", false},
	}

	for _, tc := range tests {
		fakeCertData := [][]fakeCertData{
			[]fakeCertData{
				fakeCertData{[]string{""}, tc.ActualCN},
			},
		}
		cert := fakeCertChain(fakeCertData)
		auth := certauth.NewAuth(certauth.Options{
			AllowedCNs: tc.AllowedCNs,
		})
		_, err := auth.CheckAuthorization(cert[0][0], nil)

		if err != nil && tc.ShouldValidate {
			t.Fatalf("Expected AllowedCNs (%v) and ActualCN (%v) to pass validation, but it failed: err: %s", tc.AllowedCNs, tc.ActualCN, err)
		}

		if err == nil && !tc.ShouldValidate {
			t.Fatalf("Expected AllowedCNs (%v) and ActualCN (%v) to failed validation, but it passed.", tc.AllowedCNs, tc.ActualCN)
		}
	}
}

var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("bar"))
})

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

func makeTestCNRouterHandler(t *testing.T) httprouter.Handle {
	return httprouter.Handle(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		param := ps.ByName("test_param")
		val, ok := r.Context().Value(certauth.HasAuthorizedCN).(string)
		if !ok {
			t.Fatal("Context did not set context HasAuthorizedCN")
		}
		expect(t, val, param)
		fmt.Fprintf(w, "%s", param)
	})
}

func TestMiddleware(t *testing.T) {
	allowedFakeCertData := [][]fakeCertData{
		[]fakeCertData{
			fakeCertData{[]string{"endpoint"}, "foo.com"},
		},
	}
	allowedCert := fakeCertChain(allowedFakeCertData)
	failedFakeCertData := [][]fakeCertData{
		[]fakeCertData{
			fakeCertData{[]string{"site"}, "foo.com"},
			fakeCertData{[]string{"endpoint"}, "foo.com"},
		},
	}
	failedCert := fakeCertChain(failedFakeCertData)

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
	testRouterHandler := httprouter.Handle(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Fprintf(w, "%s", ps.ByName("test_param"))
	})
	allowedFakeCertData := [][]fakeCertData{
		[]fakeCertData{
			fakeCertData{[]string{"endpoint"}, "foo.com"},
		},
	}
	allowedCert := fakeCertChain(allowedFakeCertData)
	failedFakeCertData := [][]fakeCertData{
		[]fakeCertData{
			fakeCertData{[]string{"site"}, "foo.com"},
			fakeCertData{[]string{"endpoint"}, "foo.com"},
		},
	}
	failedCert := fakeCertChain(failedFakeCertData)

	auth := certauth.NewAuth(certauth.Options{
		AuthorizationCheckers: []certauth.AuthorizationChecker{
			certauth.AllowOUsandCNs([]string{"endpoint", "titan"}, []string{"foo.com"}),
		},
	})

	name_param := "lorem"
	url1 := fmt.Sprintf("https://foo.bar/foo/%s/bar", name_param)
	url2 := fmt.Sprintf("https://foo.bar/test/%s/cn", "foo.com")
	rtr := httprouter.New()
	rtr.GET("/foo/:test_param/bar", auth.RouterHandler(testRouterHandler))
	rtr.GET("/test/:test_param/cn", auth.RouterHandler(makeTestCNRouterHandler(t)))

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
