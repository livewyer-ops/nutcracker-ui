package nutcracker // import "github.com/nutmegdevelopment/nutcracker-ui/nutcracker"

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// API represents a nutcracker API
type API struct {
	url   url.URL
	req   *http.Request
	creds *Creds
}

// Creds is an interface to send credentials
type Creds struct {
	Username string
	Password string
	Admin    bool `json:"-"`
}

// APIReq is a convenient way of passing a request
type APIReq map[string]interface{}

//NewAPIReq returns a new APIReq
func NewAPIReq() APIReq {
	return make(APIReq)
}

// Set sets a value in a request.
func (a APIReq) Set(key string, value interface{}) APIReq {
	a[key] = value
	return a
}

// NewAPI returns a new nutcracker API.  If creds are nil, an unauthenticated
// request will be made.
func NewAPI(creds *Creds, server string) *API {
	return &API{
		url: url.URL{
			Host:   server,
			Scheme: "https",
		},
		creds: creds,
	}
}

// Get sents a GET request
func (a *API) Get(path string) (response []byte, err error) {
	a.url.Path = path

	req, err := http.NewRequest("GET", a.url.String(), nil)
	if err != nil {
		return
	}

	return a.request(req)
}

// Post sends a POST request
func (a *API) Post(path string, data APIReq) (response []byte, err error) {
	a.url.Path = path

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		json.NewEncoder(pw).Encode(&data)
	}()

	req, err := http.NewRequest("POST", a.url.String(), pr)
	if err != nil {
		return
	}
	defer pr.Close()
	response, err = a.request(req)
	return
}

// Delete sents a DELETE request
func (a *API) Delete(path string) (response []byte, err error) {
	a.url.Path = path

	req, err := http.NewRequest("DELETE", a.url.String(), nil)
	if err != nil {
		return
	}

	return a.request(req)
}

func (a *API) request(req *http.Request) (response []byte, err error) {
	req.Close = true
	if a.creds != nil {
		req.Header.Set("X-Secret-ID", a.creds.Username)
		req.Header.Set("X-Secret-Key", a.creds.Password)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		err = errors.New("API Error: " + resp.Status)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	return
}

type MetricVal struct {
	Keys    int
	Secrets int
	Views   int
	Sealed  bool
	date    time.Time
}

type Metrics struct {
	sync.Mutex
	history []MetricVal
	client  *API
}

// NewMetrics creates a new metric poller
func NewMetrics(server string) (m *Metrics) {
	m = new(Metrics)
	m.client = NewAPI(nil, server)
	return
}

// Update updates the metric data from the server
func (m *Metrics) Update() (err error) {
	m.Lock()
	defer m.Unlock()

	data, err := m.client.Get("/metrics")
	if err != nil {
		return
	}

	var point MetricVal

	err = json.Unmarshal(data, &point)
	if err != nil {
		return
	}

	// Set the metric retrieval time
	point.date = time.Now()

	m.history = append(m.history, point)
	return
}

// Latest returns the latest metric data set
func (m *Metrics) Latest() MetricVal {
	return m.history[len(m.history)-1]
}
