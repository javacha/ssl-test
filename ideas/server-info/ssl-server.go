package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func help() {
	fmt.Print("no args!  Must inform <server>:<port> to list server certs. \n\n\n")
	return
}

func checkExpired(from time.Time, until time.Time) bool {
	actualDate := time.Now()
	expired := true
	if actualDate.After(from) && actualDate.Before(until) {
		expired = false
	}
	return expired
}

func main() {
	// Replace with your server's address and port
	//serverAddr := "aso-dev-ar.work-02.platform.bbva.com:443"

	args := os.Args
	if len(args) < 2 {
		help()
		return
	}
	serverAddr := args[1]

	// Connect to the server
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Configure TLS
	config := &tls.Config{
		ServerName:         "aso-dev-ar.work-02.platform.bbva.com", // Replace with your server's hostname
		InsecureSkipVerify: false,                                  // Set to true only for testing with self-signed certificates
	}

	tlsConn := tls.Client(conn, config)
	defer tlsConn.Close()

	// Handshake with the server
	if err := tlsConn.Handshake(); err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}

	// Get the server's certificates
	certs := tlsConn.ConnectionState().PeerCertificates

	// Print each certificate
	//fmt.Printf(">>> Connected to %s\n\n", config.ServerName)
	fmt.Printf(">>> Listing server certificates\n\n")
	certId := 0
	for _, cert := range certs {
		fmt.Printf("certificate %d\n", certId)
		fmt.Printf("Subject: %s\n", cert.Subject)
		fmt.Printf("Issuer: %s\n", cert.Issuer)
		fmt.Printf("NotBefore: %s\n", cert.NotBefore)
		fmt.Printf("NotAfter: %s\n", cert.NotAfter)
		isValid := checkExpired(cert.NotBefore, cert.NotAfter)
		fmt.Printf("Expired: %v\n", isValid)
		fmt.Printf("DNSNames: %v\n", cert.DNSNames)
		//fmt.Printf("EmailAddresses: %v\n", cert.EmailAddresses)
		//fmt.Printf("IPAddresses: %v\n", cert.IPAddresses)
		//fmt.Printf("URIs: %v\n", cert.URIs)
		//fmt.Printf("IsCA: %v\n", cert.IsCA)
		//fmt.Printf("KeyUsage: %v\n", cert.KeyUsage)
		//fmt.Printf("Extensions: %v\n", cert.Extensions)

		fmt.Println("---------------------------------------------------")
		certId++
	}
}
