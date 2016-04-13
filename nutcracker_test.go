package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Simple echoserver that returns the request.  Requires auth headers set to testid/testkey
func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if r.Header.Get("X-Secret-ID") != "testid" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("X-Secret-Key") != "testkey" {
			w.WriteHeader(401)
			return
		}
		for key, value := range r.Header {
			for i := range value {
				w.Header().Add(key, value[i])
			}
		}
		w.Write(reqBody)
	}))
}

func TestAPI(t *testing.T) {

	ts := echoServer()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	assert.NoError(t, err)
	nutcrackerServer = u.Host

	a := newAPI(nil)
	a.url.Scheme = "http"

	_, err = a.Get("test/url")
	assert.EqualError(t, err, "API Error: 401 Unauthorized")

	a = newAPI(&Creds{Username: "testid", Password: "testkey"})
	a.url.Scheme = "http"

	_, err = a.Get("test/url")
	assert.NoError(t, err)

	resp, err := a.Post("test/url", apiReq{"name": "test"})
	assert.NoError(t, err)
	assert.Equal(t, []byte(`{"name":"test"}`+"\n"), resp)

}
