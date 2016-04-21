package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"html/template"
	"io/ioutil"
	stdLog "log"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/nutmegdevelopment/nutcracker-ui/nutcracker"
)

var (
	csrfWrapper        func(http.Handler) http.Handler
	nutcrackerServer   string
	nutcrackerKey      string
	nutcrackerCertName string
	listen             string
	ssl                bool
	tmpl               *template.Template
	htmlDir            = "html/"
	assetsDir          = "assets/"
	nutcrackerUser     = "nutcracker-ui"
	nutcrackerCSRFName = "nutcracker-ui-csrf"
	metrics            *nutcracker.Metrics
	metricRefreshRate  = 30 * time.Second
)

func init() {
	flag.StringVar(&nutcrackerServer, "backend", "localhost:8443", "Nutcracker Backend")
	flag.StringVar(&nutcrackerKey, "key", "", "Nutcracker key")
	flag.StringVar(&nutcrackerCertName, "cert", "", "Name of TLS cert in nutcracker")
	flag.BoolVar(&ssl, "secure", true, "Use this to disable TLS.  Do not use in production!")
	flag.StringVar(&listen, "listen", "0.0.0.0:8443", "Listen address")
	flag.Parse()

	// Load base HTML templates at startup
	tmpl = template.New("main")
	_, err := tmpl.ParseGlob(htmlDir + "*.html")
	if err != nil {
		panic(err.Error())
	}

	metrics = nutcracker.NewMetrics(nutcrackerServer)
}

func updateMetrics() {
	for {

		err := metrics.Update()
		if err != nil {
			log.Error("Metric update error: ", err)
		}

		time.Sleep(metricRefreshRate)
	}
}

func addRoutes(r *mux.Router) {
	r.HandleFunc("/{type:(css|js|fonts|img)}/{file:.*}", Assets).Methods("GET")
	r.HandleFunc("/login", Login).Methods("GET", "POST")
	r.HandleFunc("/logout", Logout).Methods("GET")
	r.HandleFunc("/", Home).Methods("GET", "POST").Name("Home")
	r.HandleFunc("/secrets", Secrets).Methods("GET", "POST").Name("Secrets")
	r.HandleFunc("/keys", Keys).Methods("GET", "POST").Name("Keys")
	r.HandleFunc("/admin", Admin).Methods("GET", "POST").Name("Admin")
}

func getNutcrackerCert(api *nutcracker.API) (cert tls.Certificate, err error) {
	buf, err := api.Post("/secrets/view", nutcracker.NewAPIReq().Set("name", nutcrackerCertName))
	if err != nil {
		return
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(buf)-8))
	n, err := base64.StdEncoding.Decode(decoded, buf[8:])

	decoded = decoded[:n]

	var certList [][]byte

	for len(decoded) > 0 {
		var block *pem.Block
		block, decoded = pem.Decode(decoded)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			// letsencrypt returns the bundle in the wrong order.
			// make a list and reverse it.
			certList = append(certList, block.Bytes)

		}

		if block.Type == "PRIVATE KEY" {

			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				continue
			}

		}

		// Reverse the list
		for i := len(certList) - 1; i >= 0; i-- {
			cert.Certificate = append(cert.Certificate, certList[i])
		}

	}

	return

}

// Tanke from crypto/x509
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}

func main() {

	serverCreds := &nutcracker.Creds{
		Username: nutcrackerUser,
		Password: nutcrackerKey,
	}

	api := nutcracker.NewAPI(
		serverCreds,
		nutcrackerServer)

	resp, err := api.Post(
		"/secrets/view",
		nutcracker.NewAPIReq().Set(
			"name",
			nutcrackerCSRFName))
	if err != nil {
		log.Fatal(err)
	}

	csrfWrapper = csrf.Protect(resp, csrf.Secure(ssl))

	// Start metric fetcher
	go updateMetrics()

	r := mux.NewRouter()
	addRoutes(r)

	server := new(http.Server)
	server.Handler = context.ClearHandler(csrfWrapper(r))

	server.ErrorLog = new(stdLog.Logger)
	server.ErrorLog.SetOutput(ioutil.Discard)

	if ssl {

		var cert tls.Certificate
		var err error

		if nutcrackerCertName == "" {
			// Use a self-signed cert
			cert, err = GenCert()
		} else {
			cert, err = getNutcrackerCert(api)
		}
		if err != nil {
			log.Fatal(err)
		}

		sock, err := Socket(listen, cert)
		if err != nil {
			log.Fatal(err)
		}

		server.Serve(sock)

	} else {
		server.Addr = listen
		server.ListenAndServe()
	}
}
