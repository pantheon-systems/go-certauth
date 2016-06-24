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

	"github.com/davecgh/go-spew/spew"
	"github.com/pantheon-systems/go-certauth"
)

var (
	authedCert = &x509.Certificate{
		Subject: pkix.Name{
			OrganizationalUnit: []string{"thiunit", "thatunit", "someunit"},
		},
	}
	unauthedCert = &x509.Certificate{
		Subject: pkix.Name{
			OrganizationalUnit: []string{"thiunit", "thatunit"},
		},
	}
	certChain1 = []*x509.Certificate{unauthedCert, authedCert}
	certChain2 = []*x509.Certificate{unauthedCert, unauthedCert}
	chains     = [][]*x509.Certificate{
		certChain1,
		certChain2,
	}
)

func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func TestValidateOU(t *testing.T) {
	ouAndcnAuth := certauth.NewAuth(certauth.Options{
		AllowedOUs: []string{"someunit", "bestunit"},
		AllowedCNs: []string{"foo.com", "bar.com"},
	})

	if err := ouAndcnAuth.ValidateOU(chains); err != nil {
		t.Fatal("Expected OU to pass, but it failed: ", err)
	}

	if err := ouAndcnAuth.ValidateCN(chains); err == nil {
		t.Fatal("Expected CN to fail, but it didn't", spew.Sdump(ouAndcnAuth), spew.Sdump(chains))
	}
}

var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("bar"))
})

func TestMiddleWare(t *testing.T) {
	a := certauth.NewAuth(certauth.Options{
		AllowedOUs: []string{"someunit", "bestunit"},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	url := "https://foo.bar/foo"

	// failed auth
	req, _ := http.NewRequest("GET", url, nil)
	req.TLS = &tls.ConnectionState{}
	req.TLS.VerifiedChains = [][]*x509.Certificate{certChain2}
	w := httptest.NewRecorder()
	a.Handler(testHandler).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusForbidden)

	//passed auth
	w = httptest.NewRecorder()
	req.TLS.VerifiedChains = [][]*x509.Certificate{certChain1}
	a.Handler(testHandler).ServeHTTP(w, req)
	expect(t, w.Code, http.StatusOK)
	expect(t, w.Body.String(), "bar")

}
