package main

import (
	"flag"
	"html/template"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

var (
	csrfWrapper        func(http.Handler) http.Handler
	nutcrackerServer   string
	nutcrackerKey      string
	listen             string
	ssl                bool
	tmpl               *template.Template
	htmlDir            = "html/"
	assetsDir          = "assets/"
	nutcrackerUser     = "nutcracker-ui"
	nutcrackerCSRFName = "nutcracker-ui-csrf"
	metrics            *Metrics
	metricRefreshRate  = 30 * time.Second
)

func init() {
	flag.StringVar(&nutcrackerServer, "backend", "localhost:8443", "Nutcracker Backend")
	flag.StringVar(&nutcrackerKey, "key", "", "Nutcracker key")
	flag.BoolVar(&ssl, "secure", true, "Use this to disable TLS.  Do not use in production!")
	flag.StringVar(&listen, "listen", "0.0.0.0:8443", "Listen address")
	flag.Parse()

	// Load base HTML templates at startup
	tmpl = template.New("main")
	_, err := tmpl.ParseGlob(htmlDir + "*.html")
	if err != nil {
		panic(err.Error())
	}

	metrics = new(Metrics)
}

func updateMetrics() {
	for {

		err := metrics.update()
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

func server() {
	// Start metric fetcher
	go updateMetrics()

	r := mux.NewRouter()
	addRoutes(r)

	server := new(http.Server)
	server.Handler = context.ClearHandler(csrfWrapper(r))

	if ssl {

		cert, err := GenCert()
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

func main() {

	serverCreds := &Creds{
		Username: nutcrackerUser,
		Password: nutcrackerKey,
	}

	resp, err := newAPI(serverCreds).Post("/secrets/view", apiReq{"name": nutcrackerCSRFName})
	if err != nil {
		log.Fatal(err)
	}

	csrfWrapper = csrf.Protect(resp, csrf.Secure(ssl))

	server()
}
