package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {

	// Check args
	args := os.Args
	if len(args) < 2 {
		fmt.Println("no args!  Must inform URL to test. \n\n")
		fmt.Println("Put server CAs in file myTrustStore.pem. \n")
		return
	}
	url := args[1]

	// Load your server's certificate
	certFile := "myTrustStore.pem"
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Println("Error reading certificate:", err)
		return
	}

	// Create a certificate pool and add your server's certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert)

	// Create a custom HTTP client with your certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	// Make an HTTPS request (replace with your API URL)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("\nConnected  OK!\n")

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Printf("Response from %s:\n%s\n", url, body)
}
