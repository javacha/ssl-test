package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func resolveProxy(targetURL, proxyURL string, showProxy bool) (*url.URL, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("URL inválida: %v", err)
	}

	var proxy *url.URL
	if proxyURL != "" {
		proxy, err = url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("proxy inválido: %v", err)
		}
	} else {
		req := &http.Request{URL: u}
		proxy, err = http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, fmt.Errorf("error resolviendo proxy: %v", err)
		}
	}

	if showProxy {
		if proxy != nil {
			fmt.Printf("[DEBUG] Usando proxy: %s\n", proxy.String())
		} else {
			fmt.Println("[DEBUG] No se usará proxy")
		}
	}

	return proxy, nil
}

func fetchCerts(targetURL string, proxyURL string, showProxy bool) error {
	// Parseamos URL y extraemos host:puerto
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("URL inválida: %v", err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "http" {
			host += ":80"
		} else {
			host += ":443"
		}
	}

	proxy, err := resolveProxy(targetURL, proxyURL, showProxy)
	if err != nil {
		return err
	}

	var conn net.Conn
	if proxy != nil {
		conn, err = net.DialTimeout("tcp", proxy.Host, 10*time.Second)
		if err != nil {
			return fmt.Errorf("error conectando proxy: %v", err)
		}

		auth := ""
		if proxy.User != nil {
			user := proxy.User.Username()
			pass, _ := proxy.User.Password()
			auth = "Proxy-Authorization: Basic " +
				base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
		}

		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", host, host, auth)
		_, err = conn.Write([]byte(req))
		if err != nil {
			return fmt.Errorf("error enviando CONNECT: %v", err)
		}

		br := bufio.NewReader(conn)
		resp, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error leyendo proxy resp: %v", err)
		}
		if !strings.Contains(resp, "200") {
			return fmt.Errorf("proxy no permitió CONNECT: %s", resp)
		}
	} else {
		conn, err = net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			return fmt.Errorf("error conectando directo: %v", err)
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         u.Hostname(),
	})
	err = tlsConn.Handshake()
	if err != nil {
		return fmt.Errorf("handshake TLS falló: %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	for i, cert := range state.PeerCertificates {
		fmt.Printf("Cert %d:\n", i)
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  NotBefore: %s\n", cert.NotBefore)
		fmt.Printf("  NotAfter: %s\n", cert.NotAfter)
	}
	return nil
}

func fetchURL(targetURL string, proxyURL string, caCertPool *x509.CertPool, showProxy bool) error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caCertPool},
	}

	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return fmt.Errorf("proxy inválido: %v", err)
		}
		transport.Proxy = http.ProxyURL(pu)
		if showProxy {
			fmt.Printf("[DEBUG] Usando proxy explícito: %s\n", pu.String())
		}
	} else {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			pu, err := http.ProxyFromEnvironment(req)
			if showProxy {
				if pu != nil {
					fmt.Printf("[DEBUG] Usando proxy de env: %s\n", pu.String())
				} else {
					fmt.Println("[DEBUG] No se usará proxy")
				}
			}
			return pu, err
		}
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get(targetURL)
	if err != nil {
		return fmt.Errorf("GET falló: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTP %d:\n%s...\n", resp.StatusCode, string(body[:200]))
	return nil
}

func main() {
	mode := flag.String("mode", "certs", "certs (certificados) o fetch (GET completo)")
	target := flag.String("target", "https://www.google.com", "URL completa (https://...)")
	proxy := flag.String("proxy", "", "Proxy explícito (sino usa env http_proxy/https_proxy/no_proxy)")
	showProxy := flag.Bool("showproxy", false, "Mostrar qué proxy se usará realmente")
	flag.Parse()

	switch *mode {
	case "certs":
		if err := fetchCerts(*target, *proxy, *showProxy); err != nil {
			fmt.Println("Error:", err)
		}
	case "fetch":
		caCertPool, _ := x509.SystemCertPool()
		if err := fetchURL(*target, *proxy, caCertPool, *showProxy); err != nil {
			fmt.Println("Error:", err)
		}
	default:
		fmt.Println("Modo inválido: usa -mode=certs o -mode=fetch")
	}
}
