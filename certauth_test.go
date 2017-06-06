package certauth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

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

func TestValidateOU(t *testing.T) {
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
		err := auth.ValidateOU(cert[0][0])

		if err != nil && tc.ShouldValidate {
			t.Fatalf("Expected AllowedOUs (%v) and ActualOUs (%v) to pass validation, but it failed: err: %s", tc.AllowedOUs, tc.ActualOUs, err)
		}

		if err == nil && !tc.ShouldValidate {
			t.Fatalf("Expected AllowedOUs (%v) and ActualOUs (%v) to failed validation, but it passed.", tc.AllowedOUs, tc.ActualOUs)
		}
	}
}

func TestValidateCN(t *testing.T) {
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
		err := auth.ValidateCN(cert[0][0])

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

func TestMiddleWare(t *testing.T) {
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

	testCtxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val, ok := r.Context().Value(certauth.HasAuthorizedCN).(string)
		if !ok {
			t.Fatal("Context did not set context HasAuthorizedCN")
		}
		expect(t, val, "foo.com")
	})

	w = httptest.NewRecorder()
	auth.Handler(testCtxHandler).ServeHTTP(w, req)

}

// @TODO(joe): TestMiddleware using the RouterHandler too?
