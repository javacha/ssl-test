package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func help() {
	fmt.Print("")
	fmt.Print("ssl-test | List server certificates and test SSL connection. ")
	fmt.Print("")
	fmt.Print("Usage:")
	fmt.Print("  ssl-test <url> [cacerts]")
	fmt.Print("")
	fmt.Print("      url: server url")
	fmt.Print("  cacerts: optional custom CAcerts")
	fmt.Print("")
	fmt.Print("")
}

// obtiene el server name desde el argumento de commandLine
func getServerURL(baseurl string) string {
	baseurl = strings.Replace(baseurl, "http://", "", -1)
	baseurl = strings.Replace(baseurl, "https://", "", -1)

	// elimina path
	where := strings.Index(baseurl, "/")
	if where > -1 {
		baseurl = baseurl[0:where]
	}
	return baseurl
}

func checkExpired(from time.Time, until time.Time) bool {
	actualDate := time.Now()
	expired := true
	if actualDate.After(from) && actualDate.Before(until) {
		expired = false
	}
	return expired
}

func printCertificate(cert *x509.Certificate, idx int) {
	fmt.Println(">   ")
	fmt.Printf(">   certificate %d\n", idx)
	fmt.Printf(">   Subject: %s\n", cert.Subject)
	fmt.Printf(">   Issuer: %s\n", cert.Issuer)
	fmt.Printf(">   NotBefore: %s\n", cert.NotBefore)
	fmt.Printf(">   NotAfter: %s\n", cert.NotAfter)
	isValid := checkExpired(cert.NotBefore, cert.NotAfter)
	fmt.Printf(">   Expired: %v\n", isValid)
	fmt.Printf(">   DNSNames: %v\n", cert.DNSNames)
	//fmt.Printf("EmailAddresses: %v\n", cert.EmailAddresses)
	//fmt.Printf("IPAddresses: %v\n", cert.IPAddresses)
	//fmt.Printf("URIs: %v\n", cert.URIs)
	//fmt.Printf("IsCA: %v\n", cert.IsCA)
	//fmt.Printf("KeyUsage: %v\n", cert.KeyUsage)
	//fmt.Printf("Extensions: %v\n", cert.Extensions)

	//fmt.Println("> -----------------------------")
}

func listServerCerts(serverAddr string) {
	certs := getServerCerts(serverAddr)
	fmt.Println("")
	fmt.Println("")
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	fmt.Println(">>> Listing server certificates..... ")
	fmt.Println(">")
	certId := 0
	for _, cert := range certs {
		printCertificate(cert, certId)
		certId++
	}
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>")
}

func listCAs(caCertPool *x509.CertPool) {
	fmt.Println("")
	fmt.Println("")
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	fmt.Println(">>> Listing server certificates..... ")
	fmt.Println(">")
	certId := 0
	for _, subj := range caCertPool.Subjects() {
		cert, _ := x509.ParseCertificate(subj)
		printCertificate(cert, certId)
		certId++
	}
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>")
}

func getServerCerts(serverAddr string) []*x509.Certificate {
	// Connect to the server
	conn, err := net.Dial("tcp", serverAddr+":443")
	if err != nil {
		fmt.Println("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Configure TLS
	config := &tls.Config{
		ServerName:         serverAddr,
		InsecureSkipVerify: false,
	}

	tlsConn := tls.Client(conn, config)
	defer tlsConn.Close()

	// Handshake with the server
	if err := tlsConn.Handshake(); err != nil {
		fmt.Println("TLS handshake failed: %v", err)
		os.Exit(-2)
	}

	// Get the server's certificates
	return tlsConn.ConnectionState().PeerCertificates
}

func getParams(args []string) (url, cacerts string) {
	if len(args) < 2 {
		help()
		os.Exit(1)
	}
	url = args[1]
	if len(args) == 3 {
		cacerts = args[2]
	}
	return getServerURL(url), cacerts
}

// Carga el custom cacerts
func loadCacerts(certFile string) *x509.CertPool {
	fmt.Println(" ")
	fmt.Println(" ")
	if len(certFile) == 0 {
		fmt.Println(">>> Using system CAs")
		return nil
	}

	// Load your cacerts file
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Println("Error reading file:", err)
			os.Exit(-2)
		}
	}

	caCertPool := x509.NewCertPool()
	if len(cert) > 0 {
		// Create a certificate pool and add your cacerts file
		caCertPool.AppendCertsFromPEM(cert)
		fmt.Println(">>> Using custom truststore ", certFile)
	}
	fmt.Println("")
	return caCertPool
}

func removeURLFromError(error string) string {
	where := strings.Index(error, ":")
	error = error[where+1:]
	where = strings.Index(error, ":")
	return error[where+1:]
}

func sslConnect(url string, caCertPool *x509.CertPool) {
	// Create a custom HTTP client with your certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	//fmt.Println("")
	fmt.Println("")
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	fmt.Println(">>> Testing SSL connection..... ")
	fmt.Println(">")
	fmt.Println(">")

	connectOK := true
	resp, err := client.Get("https://" + url)
	if err != nil {
		connectOK = false
	}

	if connectOK {
		defer resp.Body.Close()

		fmt.Println(">   Connected  OK!")
		body, err := io.ReadAll(resp.Body) // Read the response body
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}
		fmt.Println(">   Response from %s", url)
		fmt.Println(">  ", resp.Status)
		fmt.Printf(">   %s", body)
	} else {
		fmt.Println(">   Connection failed!")
		fmt.Printf(">   Message %s\n", removeURLFromError(err.Error()))
	}
	fmt.Println(">")
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>")

}

func main() {

	var (
		url     string
		cacerts string
	)

	url, cacerts = getParams(os.Args)

	caCertPool := loadCacerts(cacerts)

	sslConnect(url, caCertPool)

	listServerCerts(url)

	//listCAs(caCertPool)
}
