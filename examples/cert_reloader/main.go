package main

/*
Example usage of the certutils.CertReloader providing on the fly cert reloads

	$ go run main.go &

	$ curl https://localhost:18080/
	hello, world!

	$ touch ../test-fixtures/server.pem
	2017/09/04 07:28:35 Reloading TLS certificates...
  2017/09/04 07:28:35 Loading TLS certificates...
  2017/09/04 07:28:35 Reloading TLS certificates complete.
*/

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"

	"github.com/pantheon-systems/go-certauth/certutils"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "hello, world!\n")
}

func main() {
	router := http.HandlerFunc(HelloServer)

	// load CA cert. (NOTE: on the fly reloading of CA certs is not currently supported)
	caCerts, err := certutils.LoadCACertFile("../test-fixtures/ca.crt")
	if err != nil {
		log.Fatalf("Unable to load ca.crt: %s", err)
	}

	// setup a cert reloader using our TLS key and cert
	reloader, err := certutils.NewCertReloader("../test-fixtures/server.pem", "../test-fixtures/server.pem")
	if err != nil {
		log.Fatalf("Unable to load TLSkey+cert: %s", err)
	}

	// create a TLS server
	cfg := certutils.TLSServerConfig{
		CertPool:    caCerts,
		BindAddress: "",
		Port:        18080,
		Router:      router,
	}
	server := certutils.NewTLSServer(cfg)
	server.TLSConfig.ClientAuth = tls.NoClientCert // Disable client cert requirement for this example

	// Modify the server's TLSConfig (*tls.Config) to support on the fly cert reloading
	reloader.TLSConfigApplyReloader(server.TLSConfig)
	// Handle any errors from the cert reloader. An app may choose to cleanup
	// and shutdown at this point. Or, just log any errors and keep running.
	// The cert loaded at startup will continue to be used, although it may be expired.
	go func() {
		for e := range reloader.Error {
			log.Printf("Error from cert reloader: %s", e)
		}
	}()

	log.Fatal(server.ListenAndServeTLS("", ""))
}
