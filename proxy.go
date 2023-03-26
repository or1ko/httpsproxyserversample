package main

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	username = "user"
	password = ""
)

func checkProxyAuth(r *http.Request) bool {
	proxyAuthHeader := r.Header.Get("Proxy-Authorization")
	if proxyAuthHeader == "" {
		return false
	}

	authParts := strings.SplitN(proxyAuthHeader, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		return false
	}

	authDecoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		return false
	}

	authStr := string(authDecoded)
	authCreds := strings.SplitN(authStr, ":", 2)
	if len(authCreds) != 2 || authCreds[0] != username || authCreds[1] != password {
		return false
	}

	return true
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	if !checkProxyAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !checkProxyAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	server := &http.Server{
		Addr: ":18080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	log.Println("Starting HTTP proxy server on :18080")
	log.Fatal(server.ListenAndServe())
}
