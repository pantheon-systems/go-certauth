package main

/*
Example using go stdlib net/rpc:

    $ go run main.go &

    $ curl -kE ../test-fixtures/client1.pem https://localhost:18088/
    hello, world!

    $ curl -kE ../test-fixtures/client2.pem https://localhost:18088/
    Authentication Failed

    ### NOTE: curl on macOS might require using the .p12 file instead of the .pem:
    $ curl -kE ../test-fixtures/client1.p12:password https://localhost:18088/
*/

import (
	"crypto/rand"
	"crypto/tls"
	"log"
	"net"
	"net/rpc"

	"github.com/pantheon-systems/go-certauth/certutils"
)

func main() {
	if err := rpc.Register(new(Foo)); err != nil {
		log.Fatal("Failed to register RPC method")
	}

	caCerts, err := certutils.LoadCACertFile("../test-fixtures/ca.crt")
	if err != nil {
		log.Fatalf("Unable to load ca.crt: %s", err)
	}

	serverCert, err := tls.LoadX509KeyPair("../test-fixtures/server.pem", "../test-fixtures/server.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCerts,
	}
	config.Rand = rand.Reader
	config.BuildNameToCertificate()
	service := "127.0.0.1:18088"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("Error casting!")
	}
	err := tlsConn.Handshake()
	if err != nil {
		log.Fatalf("server: handshake: %s", err)
	}
	state := tlsConn.ConnectionState()
	for _, a := range state.VerifiedChains {
		log.Printf("%+v", a)
		for _, b := range a {
			log.Printf("%+v", b)
		}
	}
	rpc.ServeConn(tlsConn)
	log.Println("server: conn: closed")
}

type Foo bool

type Result struct {
	Data int
}

func (f *Foo) Bar(args *string, res *Result) error {
	res.Data = len(*args)
	log.Printf("Received %q, its length is %d", *args, res.Data)
	//return fmt.Errorf("Whoops, error happened")
	return nil
}
