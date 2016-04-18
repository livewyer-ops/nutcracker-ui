package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/nutmegdevelopment/nutcracker-ui/nutcracker"
)

var (
	sessionKey [32]byte
	session    *sessions.CookieStore
)

func init() {
	// Generate a secure session key
	n, err := io.ReadFull(rand.Reader, sessionKey[:])
	if err != nil {
		panic(err)
	}
	if n != 32 {
		panic("Insufficient random data")
	}
	session = sessions.NewCookieStore(sessionKey[:])
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   ssl,
	}
}

// Login page
func Login(w http.ResponseWriter, r *http.Request) {

	if validateAuth(w, r) {
		http.Redirect(w, r, "/", 302)
	}

	tmpl.New("body").ParseFiles(htmlDir + "/content/login.html")

	tmplVars := map[string]interface{}{
		"PageClass": "login-pf",
		"Body": map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		},
	}

	if r.Method == "POST" {
		if doAuth(w, r) {
			http.Redirect(w, r, "/", 302)
		} else {
			body := tmplVars["Body"]
			body.(map[string]interface{})["Message"] = "Login failed, please try again"
			tmplVars["Body"] = body
		}
	}

	err := tmpl.ExecuteTemplate(w, "main.html", tmplVars)
	if err != nil {
		log.Error(err)
	}
}

func doAuth(w http.ResponseWriter, r *http.Request) bool {
	c := new(nutcracker.Creds)
	c.Username = r.FormValue("username")
	c.Password = r.FormValue("password")
	data, err := nutcracker.NewAPI(c, nutcrackerServer).Get("/auth")
	if err != nil {
		return false
	}
	s, err := session.Get(r, "id")
	if err != nil {
		log.Error(err)
		return false
	}

	var resp map[string]bool
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return false
	}

	s.Values["name"] = c.Username
	s.Values["pass"] = c.Password
	s.Values["admin"] = resp["Admin"]
	s.Values["valid"] = true
	err = s.Save(r, w)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

// Logout page clears the session and redirects to /login
func Logout(w http.ResponseWriter, r *http.Request) {
	s, err := session.Get(r, "id")
	if err != nil {
		return
	}
	s.Options.MaxAge = -1
	s.Save(r, w)
	http.Redirect(w, r, "/login", 302)
}

// Auth checks a users session and redirects if not present
func Auth(w http.ResponseWriter, r *http.Request) bool {
	ok := validateAuth(w, r)

	if !ok {
		http.Redirect(w, r, "/login", 302)
	}

	return ok
}

// GetCreds returns the credentials for the current session
func GetCreds(r *http.Request) (c *nutcracker.Creds, err error) {
	s, err := session.Get(r, "id")
	if err != nil {
		return
	}

	if _, ok := s.Values["name"]; !ok {
		err = errors.New("Invalid session")
		return
	}
	if _, ok := s.Values["pass"]; !ok {
		err = errors.New("Invalid session")
		return
	}

	c = new(nutcracker.Creds)
	c.Username = s.Values["name"].(string)
	c.Password = s.Values["pass"].(string)
	c.Admin = s.Values["admin"].(bool)
	return
}

func validateAuth(w http.ResponseWriter, r *http.Request) bool {
	s, err := session.Get(r, "id")
	if err != nil {
		if s != nil {
			s.Options.MaxAge = -1
			s.Save(r, w)
		}
		return false
	}
	if v, ok := s.Values["valid"]; ok && v.(bool) {
		return true
	}
	return false
}
