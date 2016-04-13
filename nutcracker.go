package main

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

type api struct {
	url   url.URL
	req   *http.Request
	creds *Creds
}

type Creds struct {
	Username string
	Password string
	Admin    bool `json:"-"`
}

type apiReq map[string]interface{}

func newAPI(creds *Creds) *api {
	return &api{
		url: url.URL{
			Host:   nutcrackerServer,
			Scheme: "https",
		},
		creds: creds,
	}
}

func (a *api) Get(path string) (response []byte, err error) {
	a.url.Path = path

	req, err := http.NewRequest("GET", a.url.String(), nil)
	if err != nil {
		return
	}

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

	if resp.StatusCode > 299 {
		err = errors.New("API Error: " + resp.Status)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return
}

func (a *api) Post(path string, data apiReq) (response []byte, err error) {
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

	if resp.StatusCode > 299 {
		err = errors.New("API Error: " + resp.Status)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
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
}

func (m *Metrics) update() (err error) {
	m.Lock()
	defer m.Unlock()

	data, err := newAPI(nil).Get("/metrics")
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

func (m *Metrics) latest() MetricVal {
	return m.history[len(m.history)-1]
}
