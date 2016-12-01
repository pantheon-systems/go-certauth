package main

import (
	"crypto/tls"
	"log"
	"net/rpc"

	"github.com/pantheon-systems/go-certauth/certutils"
)

func main() {
	clientCert, err := tls.LoadX509KeyPair("../test-fixtures/client1.crt", "../test-fixtures/client1.key")
	if err != nil {
		log.Fatalf("client: loadkeys: %s", err)
	}
	caCerts, err := certutils.LoadCACertFile("../test-fixtures/ca.crt")
	if err != nil {
		log.Fatalf("Unable to load ca.crt: %s", err)
	}
	config := tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCerts,
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:18088", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())
	rpcClient := rpc.NewClient(conn)
	res := new(Result)
	if err := rpcClient.Call("Foo.Bar", "twenty-three", &res); err != nil {
		log.Fatal("Failed to call RPC", err)
	}
	log.Printf("Returned result is %d", res.Data)
}

type Result struct {
	Data int
}
