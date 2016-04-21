package main // import "github.com/nutmegdevelopment/nutcracker-ui"

import (
	"crypto/tls"
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
