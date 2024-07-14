package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gookit/color"
)

func help() {
	fmt.Println("")
	fmt.Println("ssl-test | List server certificates and test SSL connection. ")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  ssl-test <url> [cacerts]")
	fmt.Println("")
	fmt.Println("      url: server url")
	fmt.Println("  cacerts: optional custom CAcerts")
	fmt.Println("")
	fmt.Println("")
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

func printCertificateInfo(cert *x509.Certificate, idx int) {
	fmt.Println("   ")
	fmt.Printf("  certificate   %d\n", idx)
	fmt.Printf("  Subject       %s\n", cert.Subject)
	fmt.Printf("  Issuer        %s\n", cert.Issuer)
	fmt.Printf("  Serial#       %s\n", cert.SerialNumber)
	fmt.Printf("  NotBefore     %s\n", cert.NotBefore)
	fmt.Printf("  NotAfter      %s\n", cert.NotAfter)
	isValid := checkExpired(cert.NotBefore, cert.NotAfter)
	fmt.Printf("  Expired       %v\n", isValid)
	fmt.Printf("  DNSNames      %v\n", cert.DNSNames)
	//fmt.Printf("EmailAddresses %v\n", cert.EmailAddresses)
	//fmt.Printf("IPAddresses    %v\n", cert.IPAddresses)
	//fmt.Printf("URIs           %v\n", cert.URIs)
	//fmt.Printf("IsCA           %v\n", cert.IsCA)
	//fmt.Printf("KeyUsage       %v\n", cert.KeyUsage)
	//fmt.Printf("Extensions     %v\n", cert.Extensions)

	//fmt.Println(" -----------------------------")
}

func listServerCerts(serverAddr string) {
	fmt.Println("")
	fmt.Println("")
	color.Blueln("  /////////////////////////////////////////////////")
	color.Bluef("  ///       ")
	color.White.Printf("Listing server certificates")
	color.Blueln("         ///")
	color.Blueln("  /////////////////////////////////////////////////")
	fmt.Println("")
	fmt.Println("")

	certs := getServerCerts(serverAddr)

	if certs != nil {
		pemOutputFileName := serverAddr + "-CERTS.pem"
		fmt.Printf("  => Writing server certs to %s file\n", pemOutputFileName)
		certId := 0
		pemData := []byte{}
		for _, cert := range certs {
			printCertificateInfo(cert, certId)
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
			pemData = append(pemData, []byte("\n")...)
			certId++
		}
		err := os.WriteFile(pemOutputFileName, pemData, 0644)
		if err != nil {
			log.Fatalf("failed to save PEM data to file: %v", err)
		}
	}
}

// Lista los certs del custom cacert
func listCAs(certFile string) {
	if len(certFile) == 0 {
		return
	}

	pemData, err := loadCacerts(certFile)

	fmt.Println("")
	fmt.Println("")
	color.Blueln("  /////////////////////////////////////////////////")
	color.Bluef("  ///    ")
	color.White.Printf("Listing custom cacerts certificates")
	color.Blueln("    ///")
	color.Blueln("  /////////////////////////////////////////////////")
	fmt.Println("")
	fmt.Println("")

	if pemData != nil {
		fmt.Printf("  file %s\n", certFile)

		// Decode PEM data block by block
		var pemBlocks []*pem.Block
		for {
			block, rest := pem.Decode(pemData)
			if block == nil {
				break
			}
			pemBlocks = append(pemBlocks, block)
			pemData = rest
		}

		// Parse each PEM block as a certificate
		certId := 0
		for _, block := range pemBlocks {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("failed to parse certificate: %v", err)
				continue
			}
			printCertificateInfo(cert, certId)
			certId++
		}
	} else {
		fmt.Println("  Error reading custom cacerts file: ", err)
	}

}

func getServerCerts(serverAddr string) []*x509.Certificate {
	// Connect to the server
	conn, err := net.Dial("tcp", serverAddr+":443")
	if err != nil {
		fmt.Printf("Failed to connect to server => %v\n", err)
		return nil
	}
	defer conn.Close()

	// Configure TLS
	config := &tls.Config{
		ServerName:         serverAddr,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, config)
	defer tlsConn.Close()

	// Handshake with the server
	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("TLS handshake failed => %v\n", err)
		return nil
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

func removeURLFromError(error string) string {
	where := strings.Index(error, ":")
	error = error[where+1:]
	where = strings.Index(error, ":")
	return error[where+1:]
}

// Lee el archivo custom cacerts
func loadCacerts(certFile string) ([]byte, error) {
	// Load your cacerts file
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Carga un CertPool a partir de lista de certs
func createCertPool(certFile string) *x509.CertPool {
	if len(certFile) == 0 {
		return nil
	}
	cert, _ := loadCacerts(certFile)
	if cert == nil {
		return nil
	} else {
		caCertPool := x509.NewCertPool()
		if len(cert) > 0 {
			// Create a certificate pool and add your cacerts file
			caCertPool.AppendCertsFromPEM(cert)
		}
		return caCertPool
	}
}

func sslConnect(url string, cacerts string) {

	caCertPool := createCertPool(cacerts)

	// Create a custom HTTP client with your certificat
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	//Proxy: http.ProxyURL(proxyURL),

	fmt.Println(" ")
	fmt.Println(" ")
	color.Blueln("  /////////////////////////////////////////////////")
	color.Bluef("  ///         ")
	color.White.Printf("Testing SSL connection")
	color.Blueln("            ///")
	color.Blueln("  /////////////////////////////////////////////////")
	if caCertPool == nil {
		fmt.Println("  (using system CAs)")
	} else {
		fmt.Println("  (using custom truststore)")
	}

	fmt.Println("")

	connectOK := true
	resp, err := client.Get("https://" + url)
	if err != nil {
		connectOK = false
	}

	if connectOK {
		defer resp.Body.Close()

		green := color.FgGreen.Render
		fmt.Printf("  %s \n", green("Connected  OK!"))
		_, err := io.ReadAll(resp.Body) // Read the response body
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}
		fmt.Println("")

	} else {
		fmt.Print("  ")
		color.Error.Println("Connection failed!")
		fmt.Printf("  Message %s\n", removeURLFromError(err.Error()))
	}
	fmt.Println("")

}

func main() {

	var (
		url     string
		cacerts string
	)

	url, cacerts = getParams(os.Args)

	listServerCerts(url)

	listCAs(cacerts)

	sslConnect(url, cacerts)
}
