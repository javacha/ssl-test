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
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"
)

var debug bool

func help() {
	fmt.Println("")
	fmt.Println("ssl-test v1.1 | List server certificates and test SSL connection. ")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Printf("   ssl-test  [--proxy http://<server>:<port>] [--custom-ts <tls-bundle.pem>] [--debug]  <url>  \n\n")
	fmt.Println("")
	fmt.Println("      proxy: optional proxy server")
	fmt.Println("  custom-ts: optional custom CA truststore to test connection. If not informed, system truststore is used")
	fmt.Println("      debug: optional debug mode")
	fmt.Println("        url: server url")
	fmt.Println("")
	fmt.Println("")
}

// LogFunctionEntry logs the name of the function being executed
func LogFunctionEntry() {
	if debug {
		pc, _, _, _ := runtime.Caller(1) // Obtiene el caller (la función que llamó)
		funcName := runtime.FuncForPC(pc).Name()
		log.Printf("Entering function: %s", funcName)
	}
}

// obtiene el server name desde el argumento de commandLine
func getServerURL(baseurl string) string {
	LogFunctionEntry()
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
	LogFunctionEntry()
	actualDate := time.Now()
	expired := true
	if actualDate.After(from) && actualDate.Before(until) {
		expired = false
	}
	return expired
}

func formatHexWithColons(n *big.Int) string {
	LogFunctionEntry()
	// Convertimos el *big.Int a []byte (big-endian)
	bytes := n.Bytes()

	// Armamos una cadena tipo "AA:BB:CC"
	result := ""
	for i, b := range bytes {
		if i > 0 {
			result += ":"
		}
		result += fmt.Sprintf("%02X", b)
	}
	return result
}

func remainingDays(expirationDate time.Time) int {
	LogFunctionEntry()
	now := time.Now()
	diff := expirationDate.Sub(now)

	// Calcular días (redondeando hacia arriba para contar el día actual si queda parcial)
	days := int(diff.Hours() / 24)
	if diff.Hours() > float64(days*24) {
		days++
	}
	return days
}

func printCertificateInfoInScreen(cert *x509.Certificate, idx int) {
	LogFunctionEntry()
	CAIndicator := ""
	isExpired := checkExpired(cert.NotBefore, cert.NotAfter)
	fmt.Println("   ")
	if cert.IsCA {
		CAIndicator = "(CA)"
	}
	fmt.Printf("  certificate   %d  %v\n", idx, CAIndicator)
	fmt.Printf("  Subject       %s\n", cert.Subject)
	fmt.Printf("  Issuer        %s\n", cert.Issuer)
	fmt.Printf("  Serial#       %s\n", formatHexWithColons(cert.SerialNumber))
	fmt.Printf("  NotBefore     %s\n", cert.NotBefore)
	fmt.Printf("  NotAfter      %s\n", cert.NotAfter)
	if isExpired {
		fmt.Printf("  Valid         EXPIRED!!\n")
	} else {
		fmt.Printf("  Valid         OK  (%v days remaining)\n", remainingDays(cert.NotAfter))
	}
	if !cert.IsCA {
		fmt.Printf("  DNSNames      %v\n", cert.DNSNames)
	}
	//fmt.Printf("EmailAddresses %v\n", cert.EmailAddresses)
	//fmt.Printf("IPAddresses    %v\n", cert.IPAddresses)
	//fmt.Printf("URIs           %v\n", cert.URIs)
	//fmt.Printf("KeyUsage       %v\n", cert.KeyUsage)
	//fmt.Printf("Extensions     %v\n", cert.Extensions)

	//fmt.Println(" -----------------------------")
}

func add(pemData *[]byte, buff string) {
	LogFunctionEntry()
	*pemData = append(*pemData, []byte(buff)...)
}

func printCertificateInfoForPemFile(cert *x509.Certificate, pemData []byte, serverAddr string, certId int) []byte {
	LogFunctionEntry()
	if certId == 0 {
		add(&pemData, fmt.Sprintf("# Host        : %s \n", serverAddr))
	}
	add(&pemData, fmt.Sprintf("# \n"))
	add(&pemData, fmt.Sprintf("# Subject     : %s \n", cert.Subject))
	add(&pemData, fmt.Sprintf("# Issuer      : %s \n", cert.Issuer))
	add(&pemData, fmt.Sprintf("# Valid until : %s \n", cert.NotAfter))
	add(&pemData, fmt.Sprintf("# Serial#     : %s \n", formatHexWithColons(cert.SerialNumber)))

	if !cert.IsCA {
		add(&pemData, fmt.Sprintf("# DNSNames    : %v\n", cert.DNSNames))
	}
	add(&pemData, fmt.Sprintf("# \n"))
	return pemData
}

func listServerCerts(serverAddr string, proxyURL string) bool {
	LogFunctionEntry()
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
			certId++
		}
		err := os.WriteFile(pemOutputFileName, pemData, 0644)
		if err != nil {
			log.Fatalf("failed to save PEM data to file: %v", err)
		}
		return true
	}
	return false
}

// Lista los certs del custom cacert
func listCAs(certFile string) {
	LogFunctionEntry()
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

// Descarga los certs de un servidor
func getServerCerts(serverAddr string, proxyURL string) []*x509.Certificate {
	LogFunctionEntry()
	var conn net.Conn
	var err error

	var addr = serverAddr + ":443"

	parsedProxy := getProxy(proxyURL)

	if parsedProxy.Host != "" {
		// Proxy CONNECT
		conn, err = net.DialTimeout("tcp", parsedProxy.Host, 5*time.Second)
		if err != nil {
			fmt.Printf("Error connecting to proxy: %s %v\n\n", proxyURL, err)
			return nil
		}

		// Mandamos el CONNECT al proxy
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		_, err = conn.Write([]byte(req))
		if err != nil {
			fmt.Printf("Error at proxy CONNECT: %v\n\n", err)
			return nil
		}

		// Leemos respuesta del proxy
		br := bufio.NewReader(conn)
		resp, err := br.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading proxy response: %v\n\n", err)
			return nil
		}
		if !strings.Contains(resp, "200") {
			fmt.Printf("proxy CONNECT refused: %s\n\n", resp)
			return nil
		}
		// Nota: se debería consumir todos los headers hasta "\r\n", pero para demo alcanza
	} else {
		// Conexión directa
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("Error connecting direct >> %v \n\n", err)
			fmt.Printf("Tip: Try using a proxy like  proxycfg:1082 \n\n")
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
		fmt.Printf("error en handshake TLS: %v\n\n", err)
		return nil
	}
	defer tlsConn.Close()

	// Get the server's certificates
	return tlsConn.ConnectionState().PeerCertificates
}

func getParams(args []string) (url, ts, proxy string, debug bool) {
	// Definición de flags opcionales
	flag.String("proxy", "", "Proxy server (optional) ")
	flag.String("custom-ts", "", "Path to custom TS bundle (optional)")
	flag.String("debug", "", "Debug ON (optional) ")

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
	debug, _ = strconv.ParseBool(flag.Lookup("debug").Value.String())
	//customTLS = args[2]

	// Mostrar valores para verificar
	fmt.Println("")
	fmt.Println("  URL               :", url)
	fmt.Println("  Proxy             :", proxy)
	fmt.Println("  Debug             :", debug)
	fmt.Println("  Custom TLS bundle :", ts)

	return getServerURL(url), ts, proxy, debug
}

func removeURLFromError(error string) string {
	LogFunctionEntry()
	where := strings.Index(error, ":")
	error = error[where+1:]
	where = strings.Index(error, ":")
	return error[where+1:]
}

// Lee el archivo custom cacerts
func loadCacerts(certFile string) ([]byte, error) {
	LogFunctionEntry()
	// Load your cacerts file
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Carga un CertPool a partir de lista de certs
func createCertPool(certFile string) *x509.CertPool {
	LogFunctionEntry()
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

func getProxy(proxy string) *url.URL {
	LogFunctionEntry()

	// Si no tiene esquema, le agregamos http://
	if !strings.Contains(proxy, "://") {
		proxy = "http://" + proxy
	}

	parsedProxy, err := url.Parse(proxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: proxy inválido: %v\n", err)
		os.Exit(2)
	}
	return parsedProxy
}

func sslConnect(url string, cacerts string, proxyURL string) bool {
	LogFunctionEntry()

	caCertPool := createCertPool(cacerts)

	parsedProxy := getProxy(proxyURL)
	proxy := http.ProxyURL(parsedProxy)

	// Create a custom HTTP client with your certificat
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: proxy,
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
		}
	} else {
		fmt.Print("  ")
		color.Error.Println("Connection failed!")
		fmt.Printf("  Message %s\n", removeURLFromError(err.Error()))
	}
	fmt.Println("")
	return connectOK
}

func main() {
	var (
		url       string
		cacerts   string
		proxy     string
		connectOK bool
	)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	url, cacerts, proxy, debug = getParams(os.Args)
	fmt.Print("", debug)

	downloadOK := listServerCerts(url, proxy)

	if downloadOK {
		listCAs(cacerts)

		connectOK = sslConnect(url, cacerts, proxy)
		if connectOK {
			os.Exit(0)
		}
	}

	// Si llegue aca, es porque hubo un fallo
	os.Exit(1)

}
