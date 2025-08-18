package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	fmt.Printf("   ssl-test  [--proxy http://<server>:<port>] [--custom-ts <tls-bundle.pem>]  <url>  \n\n")
	fmt.Println("")
	fmt.Println("      proxy: optional proxy server")
	fmt.Println("  custom-ts: optional custom CA truststore to test connection. If not informed, system truststore is used")
	fmt.Println("        url: server url")
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

func printCertificateInfoInScreen(cert *x509.Certificate, idx int) {
	isValid := checkExpired(cert.NotBefore, cert.NotAfter)
	fmt.Println("   ")
	fmt.Printf("  certificate   %d\n", idx)
	fmt.Printf("  IsCA          %v\n", cert.IsCA)
	fmt.Printf("  Subject       %s\n", cert.Subject)
	fmt.Printf("  Issuer        %s\n", cert.Issuer)
	fmt.Printf("  Serial#       %s\n", cert.SerialNumber)
	fmt.Printf("  NotBefore     %s\n", cert.NotBefore)
	fmt.Printf("  NotAfter      %s\n", cert.NotAfter)
	fmt.Printf("  Expired       %v\n", isValid)
	fmt.Printf("  DNSNames      %v\n", cert.DNSNames)
	//fmt.Printf("EmailAddresses %v\n", cert.EmailAddresses)
	//fmt.Printf("IPAddresses    %v\n", cert.IPAddresses)
	//fmt.Printf("URIs           %v\n", cert.URIs)
	//fmt.Printf("KeyUsage       %v\n", cert.KeyUsage)
	//fmt.Printf("Extensions     %v\n", cert.Extensions)

	//fmt.Println(" -----------------------------")
}

func add(pemData *[]byte, buff string) {
	*pemData = append(*pemData, []byte(buff)...)
}

func printCertificateInfoForPemFile(cert *x509.Certificate, pemData []byte, serverAddr string, certId int) []byte {
	//pemData = append(pemData, []byte("\n")...)

	if certId == 0 {
		add(&pemData, fmt.Sprintf("# Host        : %s \n", serverAddr))
	}
	add(&pemData, fmt.Sprintf("# \n"))
	add(&pemData, fmt.Sprintf("# Subject     : %s \n", cert.Subject))
	add(&pemData, fmt.Sprintf("# Issuer      : %s \n", cert.Issuer))
	add(&pemData, fmt.Sprintf("# Vencimiento : %s \n", cert.NotAfter))
	add(&pemData, fmt.Sprintf("# Serial#     : %s \n", cert.SerialNumber))
	if !cert.IsCA {
		add(&pemData, fmt.Sprintf("# DNSNames    : %v\n", cert.DNSNames))
	}
	add(&pemData, fmt.Sprintf("# \n"))
	return pemData
}

func listServerCerts(serverAddr string, proxyURL string) {
	fmt.Println("")
	fmt.Println("")
	color.Blueln("  /////////////////////////////////////////////////")
	color.Bluef("  ///       ")
	color.White.Printf("Listing server certificates")
	color.Blueln("         ///")
	color.Blueln("  /////////////////////////////////////////////////")
	fmt.Println("")
	fmt.Println("")

	certs := getServerCerts(serverAddr, proxyURL)

	if certs != nil {
		pemOutputFileName := serverAddr + "-CERTS.pem"
		fmt.Printf("  => Writing server certs to %s file\n", pemOutputFileName)
		certId := 0
		pemData := []byte{}
		for _, cert := range certs {
			printCertificateInfoInScreen(cert, certId)
			pemData = printCertificateInfoForPemFile(cert, pemData, serverAddr, certId)
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
			//pemData = append(pemData, []byte("\n")...)
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
			printCertificateInfoInScreen(cert, certId)
			certId++
		}
	} else {
		fmt.Println("  Error reading custom cacerts file: ", err)
	}

}

func getServerCerts(serverAddr string, proxyURL string) []*x509.Certificate {
	var conn net.Conn
	var err error

	var addr = serverAddr + ":443"

	if proxyURL != "" {
		// Proxy CONNECT
		proxy, _ := url.Parse(proxyURL)
		conn, err = net.DialTimeout("tcp", proxy.Host, 10*time.Second)
		if err != nil {
			fmt.Printf("error al conectar al proxy: %s %v", proxyURL, err)
			return nil
		}

		// Mandamos el CONNECT al proxy
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		_, err = conn.Write([]byte(req))
		if err != nil {
			fmt.Printf("error enviando CONNECT: %v", err)
			return nil
		}

		// Leemos respuesta del proxy
		br := bufio.NewReader(conn)
		resp, err := br.ReadString('\n')
		if err != nil {
			fmt.Printf("error leyendo respuesta del proxy: %v", err)
			return nil
		}
		if !strings.Contains(resp, "200") {
			fmt.Printf("proxy no permitió CONNECT, resp: %s", resp)
			return nil
		}
		// Nota: se debería consumir todos los headers hasta "\r\n", pero para demo alcanza
	} else {
		// Conexión directa
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			fmt.Printf("error al conectar directo: %v \n", err)
			fmt.Printf("Tip: prueba utilizando un proxy de salida \n")
			return nil
		}
	}

	// Handshake TLS (InsecureSkipVerify: true porque vamos a validar manualmente)
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         strings.Split(addr, ":")[0], // SNI
	})
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Printf("error en handshake TLS: %v", err)
		return nil
	}
	defer tlsConn.Close()

	// Get the server's certificates
	return tlsConn.ConnectionState().PeerCertificates
}

func getParams(args []string) (url, ts, proxy string) {

	// Definición de flags opcionales
	flag.String("proxy", "", "Proxy server (optional) ")
	flag.String("custom-ts", "", "Path to custom TS bundle (optional)")

	// Parseo de flags
	flag.Parse()

	// Validar y obtener el parámetro obligatorio (url)
	if flag.NArg() < 1 {
		help()
		//fmt.Println("Error: falta el parámetro obligatorio 'url'")
		//fmt.Printf("Uso: ssl-test  [--proxy PROXY] [--custom-ts RUTA]  <url>  \n\n")
		os.Exit(1)
	}
	url = flag.Arg(0)
	proxy = flag.Lookup("proxy").Value.String()
	ts = flag.Lookup("custom-ts").Value.String()
	//customTLS = args[2]

	// Mostrar valores para verificar
	fmt.Println("URL               :", url)
	fmt.Println("Proxy             :", proxy)
	fmt.Println("Custom TLS Bundle :", ts)

	return getServerURL(url), ts, proxy
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

func getProxy(proxy string) func(*http.Request) (*url.URL, error) {
	// Normalizar proxy si se especificó
	if proxy == "" {
		// Usa configuración de entorno si no se pasa proxy
		return http.ProxyFromEnvironment
	}

	// Si no tiene esquema, le agregamos http://
	if !strings.Contains(proxy, "://") {
		proxy = "http://" + proxy
	}

	parsedProxy, err := url.Parse(proxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: proxy inválido: %v\n", err)
		os.Exit(2)
	}
	return http.ProxyURL(parsedProxy)
}

func sslConnect(url string, cacerts string, proxy string) {

	caCertPool := createCertPool(cacerts)

	// Create a custom HTTP client with your certificat
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: getProxy(proxy),
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
		proxy   string
	)

	url, cacerts, proxy = getParams(os.Args)

	fmt.Printf(proxy)

	listServerCerts(url, proxy)

	listCAs(cacerts)

	sslConnect(url, cacerts, proxy)
}
