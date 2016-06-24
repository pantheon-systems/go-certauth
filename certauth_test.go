package certauth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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

// fakeCertChain will creates a single certificate given the OU and CN values.
// The cert is then wrapped in a slice of "chains" [][]*x509.Certificate which is the
// type found in the `http.Request.TLS.VerifiedChains` attribute.
func fakeCertChain(ou []string, cn string) [][]*x509.Certificate {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			OrganizationalUnit: []string(ou),
			CommonName:         string(cn),
		},
	}
	chain := []*x509.Certificate{cert}
	chains := [][]*x509.Certificate{chain}
	return chains
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
		cert := fakeCertChain(tc.ActualOUs, "")
		auth := certauth.NewAuth(certauth.Options{
			AllowedOUs: tc.AllowedOUs,
		})
		err := auth.ValidateOU(cert)

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
		cert := fakeCertChain([]string{""}, tc.ActualCN)
		auth := certauth.NewAuth(certauth.Options{
			AllowedCNs: tc.AllowedCNs,
		})
		err := auth.ValidateCN(cert)

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
	allowedCert := fakeCertChain([]string{"endpoint"}, "foo.com")
	failedCert := fakeCertChain([]string{"site"}, "foo.com")

	auth := certauth.NewAuth(certauth.Options{
		AllowedOUs: []string{"endpoint", "titan"},
		AllowedCNs: []string{"foo.com"},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	url := "https://foo.bar/foo"

	// failed auth
	req, _ := http.NewRequest("GET", url, nil)
	req.TLS = &tls.ConnectionState{}
	req.TLS.VerifiedChains = failedCert
	w := httptest.NewRecorder()
	auth.Handler(testHandler).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusForbidden)

	//passed auth
	w = httptest.NewRecorder()
	req.TLS.VerifiedChains = allowedCert
	auth.Handler(testHandler).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusOK)
	expect(t, w.Body.String(), "bar")
}

// @TODO(joe): TestMiddleware using the RouterHandler too?
