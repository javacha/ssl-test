package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func help() {
	fmt.Print("no args!  Must inform https://<server> to test. \n\n\n")
	fmt.Print("Put server CAs into myTrustStore.pem file if needed. \n\n")
	return
}

func main() {

	// Check args
	args := os.Args
	if len(args) < 2 {
		help()
		return
	}
	url := args[1]

	// Load your server's certificate
	certFile := "myTrustStore.pem"
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Println("Error reading file:", err)
			return
		}
	}

	caCertPool := x509.NewCertPool()
	if len(cert) > 0 {
		// Create a certificate pool and add your server's certificate
		caCertPool.AppendCertsFromPEM(cert)
		fmt.Println(">>> Using custom truststore ", certFile)
	} else {
		fmt.Println(">>> Using system CAs")
		caCertPool = nil
	}
	fmt.Println("")

	// Create a custom HTTP client with your certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	connectOK := true

	// Make an HTTPS request (replace with your API URL)
	resp, err := client.Get(url)
	if err != nil {
		connectOK = false
	}

	if connectOK {
		defer resp.Body.Close()

		fmt.Print("\n<<< Connected  OK!\n\n")
		body, err := ioutil.ReadAll(resp.Body) // Read the response body
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}
		fmt.Printf("Response from %s:\n%s\n%s\n", url, resp.Status, body)
	} else {
		fmt.Print("\n<<< Error connecting!\n\n")
		fmt.Printf("Response from %s:\n%s\n", url, err)
	}
}
