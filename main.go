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
	csrfWrapper       func(http.Handler) http.Handler
	nutcrackerServer  string
	csrfKey           string
	ssl               bool
	tmpl              *template.Template
	htmlDir           = "html/"
	assetsDir         = "assets/"
	metrics           *Metrics
	metricRefreshRate = 30 * time.Second
)

func init() {
	flag.StringVar(&nutcrackerServer, "backend", "localhost:8443", "Nutcracker Backend")
	flag.StringVar(&csrfKey, "csrf", "", "CSRF Token")
	flag.BoolVar(&ssl, "secure", true, "Use this to disable TLS.  Do not use in production!")
	flag.Parse()

	// Load base HTML templates at startup
	tmpl = template.New("main")
	_, err := tmpl.ParseGlob(htmlDir + "*.html")
	if err != nil {
		panic(err)
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
	server.Addr = "0.0.0.0:8080"
	server.Handler = context.ClearHandler(csrfWrapper(r))
	log.Println(server.ListenAndServe())
}

func main() {
	csrfWrapper = csrf.Protect([]byte("csrfKey"), csrf.Secure(ssl))

	server()
}
