package main

/*
Example using github.com/julienschmidt/httprouter:

	$ go run main.go &

	$ curl -kE ../test-fixtures/client1.pem https://localhost:8080/
	Welcome!

	$ curl -kE ../test-fixtures/client2.pem https://localhost:8080/
	Welcome!

	$ curl -kE ../test-fixtures/client1.pem https://localhost:8080/hello/foo
	hello, foo!

	$ curl -kE ../test-fixtures/client2.pem https://localhost:8080/hello/foo
	Authentication Failed

	### NOTE: curl on macOS might require using the .p12 file instead of the .pem:
	$ curl -kE ../test-fixtures/client.p12:password https://localhost:8080/
*/

import (
	"fmt"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/pantheon-systems/go-certauth"
	"github.com/pantheon-systems/go-certauth/certutils"
)

func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Welcome!\n")
}

func Hello(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
}

func HelloWithoutParams(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello without params")
}

func main() {

	caCerts, err := certutils.LoadCACertFile("../test-fixtures/ca.crt")
	if err != nil {
		log.Fatalf("Unable to load ca.crt: %s", err)
	}

	auth := certauth.NewAuth(certauth.Options{
		AllowedOUs: []string{"endpoint"},
		AllowedCNs: []string{"client1"},
	})

	router := httprouter.New()
	router.GET("/", Index)
	router.GET("/hello1/:name", auth.RouterHandler(Hello))
	router.Handler("GET", "/hello2/:name", auth.Handler(http.HandlerFunc(HelloWithoutParams)))

	cfg := certutils.TLSServerConfig{
		CertPool:    caCerts,
		BindAddress: "",
		Port:        8080,
		Router:      router,
	}

	server := certutils.NewTLSServer(cfg)
	server.ListenAndServeTLS("test-fixtures/server.pem", "test-fixtures/server.pem")
}
