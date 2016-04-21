package main // import "github.com/nutmegdevelopment/nutcracker-ui"

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/nutmegdevelopment/nutcracker-ui/nutcracker"
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

var (
	extRe     *regexp.Regexp
	contentRe *regexp.Regexp
	nameRe    *regexp.Regexp
)

func init() {
	extRe = regexp.MustCompile(`\.([a-zA-Z0-9]+)$`)
	contentRe = regexp.MustCompile(`^([a-zA-Z0-9._\-=*!]+)$`)
	nameRe = regexp.MustCompile(`^([0-9a-zA-Z_\-.])+$`)
}

// Assets serves static assets
func Assets(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filePath := fmt.Sprintf(
		"%s%s/%s",
		assetsDir,
		vars["type"],
		vars["file"],
	)
	if filePath[len(filePath)-1] == '/' {
		filePath = filePath[:len(filePath)-2]
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	var contentType string
	switch vars["type"] {
	case "js":
		contentType = "text/javascript"

	case "css":
		contentType = "text/css"

	case "fonts":
		contentType = http.DetectContentType(data)

	case "img":
		// DetectContentType doesn't handle SVG properly, use extension:
		if extRe.FindString(filePath) == ".svg" {
			contentType = "image/svg+xml"
		} else {
			contentType = http.DetectContentType(data)
		}

	default:
		contentType = "text/plain"
	}

	w.Header().Set("Content-Type", contentType)

	w.Write(data)
}

type Nav struct {
	Name  string
	Link  string
	Class string
}

func navItem(r *http.Request, name, link string) (n Nav) {
	n.Name = name
	n.Link = link
	if name == mux.CurrentRoute(r).GetName() {
		n.Class = "active"
	}
	return
}

func navVars(r *http.Request) map[string]interface{} {
	vars := map[string]interface{}{
		"Menu": []Nav{
			navItem(r, "Home", "/"),
			navItem(r, "Secrets", "/secrets"),
			navItem(r, "Keys", "/keys"),
		},
	}
	// Just return basic menu if we see an error here
	c, err := GetCreds(r)
	if err != nil {
		return vars
	}
	if c.Admin {
		menu := vars["Menu"].([]Nav)
		menu = append(menu, navItem(r, "Admin", "/admin"))
		vars["Menu"] = menu
	}
	return vars
}

// Home displays the home page
func Home(w http.ResponseWriter, r *http.Request) {
	if !Auth(w, r) {
		return
	}

	if r.Method == "POST" {
		master := r.FormValue("unseal")
		switch {

		case r.FormValue("seal") == "1":
			_, err := nutcracker.NewAPI(nil, nutcrackerServer).Get("/seal")
			if err != nil {
				log.Error(err)
				http.Error(w, "Nutcracker request error", 500)
				return
			}

		case len(master) > 1:
			_, err := nutcracker.NewAPI(&nutcracker.Creds{
				Username: "master",
				Password: master,
			},
				nutcrackerServer).Get("/unseal")
			if err != nil {
				log.Error(err)
				http.Error(w, "Nutcracker request error", 500)
				return
			}
		}

		// Update metrics to show new state
		err := metrics.Update()
		if err != nil {
			log.Error(err)
		}
	}

	m := metrics.Latest()
	alert := unsealAlert(m)

	tmpl.New("body").ParseFiles(htmlDir + "/content/home.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			"SecretCount":    m.Secrets,
			"KeyCount":       m.Keys,
			"ViewCount":      m.Views,
			csrf.TemplateTag: csrf.TemplateField(r),
		},
	}

	if alert != nil {
		tmplVars["Alert"] = alert
		tmplVars["Body"].(map[string]interface{})["VaultSealed"] = true
	} else {
		tmplVars["Body"].(map[string]interface{})["VaultUnsealed"] = true
	}

	err := tmpl.ExecuteTemplate(w, "main.html", tmplVars)
	if err != nil {
		log.Error(err)
		http.Error(w, "Template rendering error", 500)
	}
}

// Secrets lists all secrets
func Secrets(w http.ResponseWriter, r *http.Request) {
	if !Auth(w, r) {
		return
	}

	creds, err := GetCreds(r)
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal session error", 500)
		return
	}

	var tableContent map[string][]interface{}
	var tableHeader []string
	var tableTitle string

	url := "/secrets/list/secrets"

	if r.Method == "POST" {

		search := strings.TrimSpace(r.FormValue("search"))
		url += "/" + search
		tableHeader, tableContent, err = keyTable(url, creds)
		tableTitle = fmt.Sprintf("Keys with access to %s secret:", search)

	} else {

		tableHeader, tableContent, err = secretTable(url, creds)
		tableTitle = "All secrets"

	}

	m := metrics.Latest()
	alert := unsealAlert(m)

	tmpl.New("body").ParseFiles(htmlDir + "/content/table.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			"PageLink":       "Secrets",
			"PageName":       "Secrets",
			"TableHeader":    tableHeader,
			"TableContent":   tableContent,
			"SearchText":     "Show secret",
			"TableTitle":     tableTitle,
			csrf.TemplateTag: csrf.TemplateField(r),
		},
	}

	if alert != nil {
		tmplVars["Alert"] = alert
	}

	err = tmpl.ExecuteTemplate(w, "main.html", tmplVars)
	if err != nil {
		log.Error(err)
		http.Error(w, "Template rendering error", 500)
	}
}

// Keys lists all keys
func Keys(w http.ResponseWriter, r *http.Request) {
	if !Auth(w, r) {
		return
	}

	creds, err := GetCreds(r)
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal session error", 500)
		return
	}

	var tableContent map[string][]interface{}
	var tableHeader []string
	var tableTitle string

	url := "/secrets/list/keys"

	if r.Method == "POST" {

		search := strings.TrimSpace(r.FormValue("search"))
		url += "/" + search
		tableHeader, tableContent, err = secretTable(url, creds)
		tableTitle = fmt.Sprintf("Secrets readable by %s key:", search)

	} else {

		tableHeader, tableContent, err = keyTable(url, creds)
		tableTitle = "All keys"

	}

	m := metrics.Latest()
	alert := unsealAlert(m)

	tmpl.New("body").ParseFiles(htmlDir + "/content/table.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			"PageLink":       "Keys",
			"PageName":       "Keys",
			"TableHeader":    tableHeader,
			"TableContent":   tableContent,
			"SearchText":     "Show key",
			"TableTitle":     tableTitle,
			csrf.TemplateTag: csrf.TemplateField(r),
		},
	}

	if alert != nil {
		tmplVars["Alert"] = alert
	}

	err = tmpl.ExecuteTemplate(w, "main.html", tmplVars)
	if err != nil {
		log.Error(err)
		http.Error(w, "Template rendering error", 500)
	}
}

// Admin performs admin functions
func Admin(w http.ResponseWriter, r *http.Request) {
	if !Auth(w, r) {
		return
	}

	creds, err := GetCreds(r)
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal session error", 500)
		return
	}

	if !creds.Admin {
		http.Error(w, "Only admin users are permitted to administrate nutcracker", 401)
		return
	}

	m := metrics.Latest()
	alert := unsealAlert(m)

	if r.Method == "POST" {

		switch r.FormValue("inputtype") {

		case "addsecret":
			alert, err = addSecret(r, creds)

		case "sharesecret":
			alert, err = shareSecret(r, creds)

		case "updatesecret":
			alert, err = updateSecret(r, creds)

		case "addkey":
			alert, err = addKey(r, creds)

		default:
			http.Error(w, "Bad input", 400)
			return
		}

	}
	if err != nil {
		log.Error(err)
	}

	tmpl.New("body").ParseFiles(htmlDir + "/content/admin.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		},
	}

	if alert != nil {
		tmplVars["Alert"] = alert
	}

	err = tmpl.ExecuteTemplate(w, "main.html", tmplVars)
	if err != nil {
		log.Error(err)
		http.Error(w, "Template rendering error", 500)
	}
}

func unsealAlert(m nutcracker.MetricVal) map[string]string {
	if m.Sealed {
		return map[string]string{
			"AlertContent": "Vault is sealed, please unseal before making changes",
		}
	}
	return nil
}

func secretTable(url string, c *nutcracker.Creds) (tableHeader []string, tableContent map[string][]interface{}, err error) {
	data, err := nutcracker.NewAPI(c, nutcrackerServer).Get(url)
	if err != nil {
		log.Error(err)
		return
	}

	// Allocate memory
	tableContent = make(map[string][]interface{})

	var list []secrets.Secret

	dec := json.NewDecoder(bytes.NewReader(data))

	for dec.More() {
		var recv []secrets.Secret
		err = dec.Decode(&recv)
		if err != nil {
			log.Error(err)
			break
		}
		list = append(list, recv...)
	}

	tableHeader = []string{
		"Name",
		"Share count",
	}

	for i := range list {
		if val, ok := tableContent[list[i].Name]; ok {
			val[0] = val[0].(int) + 1
			tableContent[list[i].Name] = val
		} else {
			tableContent[list[i].Name] = []interface{}{0}
		}
	}

	return
}

func keyTable(url string, c *nutcracker.Creds) (tableHeader []string, tableContent map[string][]interface{}, err error) {
	data, err := nutcracker.NewAPI(c, nutcrackerServer).Get(url)
	if err != nil {
		log.Error(err)
		return
	}

	// Allocate memory
	tableContent = make(map[string][]interface{})

	var list []secrets.Key

	dec := json.NewDecoder(bytes.NewReader(data))

	for dec.More() {
		var recv []secrets.Key
		err = dec.Decode(&recv)
		if err != nil {
			log.Error(err)
			break
		}
		list = append(list, recv...)
	}

	tableHeader = []string{
		"Name",
		"Type",
	}

	for i := range list {
		var keyType string
		if list[i].ReadOnly {
			keyType = "Read only"
		} else {
			keyType = "Admin"
		}
		tableContent[list[i].Name] = []interface{}{keyType}
	}
	return
}

func addSecret(r *http.Request, creds *nutcracker.Creds) (alert map[string]string, err error) {

	alert = make(map[string]string)
	reqBody := nutcracker.NewAPIReq()

	if !nameRe.MatchString(r.FormValue("name")) {
		alert["AlertContent"] = "Invalid name"
		return
	}

	reqBody.Set("name", strings.TrimSpace(r.FormValue("name")))

	msg := r.FormValue("message")

	if contentRe.MatchString(msg) {
		reqBody["message"] = msg
	} else {
		// Message with special chars/newlines/etc
		reqBody.Set("message", fmt.Sprintf("$base64$%s",
			base64.StdEncoding.EncodeToString([]byte(msg)),
		))
	}

	_, err = nutcracker.NewAPI(creds, nutcrackerServer).Post("/secrets/message", reqBody)
	if err != nil {
		alert["AlertContent"] = "Failed to create secret"
	} else {
		alert["AlertContent"] = fmt.Sprintf("Created secret %s", reqBody["name"])
	}

	return
}

func shareSecret(r *http.Request, creds *nutcracker.Creds) (alert map[string]string, err error) {

	alert = make(map[string]string)
	reqBody := make(map[string]interface{})

	if !nameRe.MatchString(r.FormValue("name")) {
		alert["AlertContent"] = "Invalid name"
		return
	}

	reqBody["name"] = strings.TrimSpace(r.FormValue("name"))
	reqBody["keyid"] = strings.TrimSpace(r.FormValue("key"))

	_, err = nutcracker.NewAPI(creds, nutcrackerServer).Post("/secrets/share", reqBody)
	if err != nil {
		alert["AlertContent"] = "Failed to share secret"
	} else {
		alert["AlertContent"] = fmt.Sprintf("Shared secret %s with key %s", reqBody["name"], reqBody["keyid"])
	}

	return
}

func updateSecret(r *http.Request, creds *nutcracker.Creds) (alert map[string]string, err error) {

	alert = make(map[string]string)
	reqBody := nutcracker.NewAPIReq()

	if !nameRe.MatchString(r.FormValue("name")) {
		alert["AlertContent"] = "Invalid name"
		return
	}

	reqBody.Set("name", strings.TrimSpace(r.FormValue("name")))

	msg := r.FormValue("message")

	if contentRe.MatchString(msg) {
		reqBody["message"] = msg
	} else {
		// Message with special chars/newlines/etc
		reqBody.Set("message", fmt.Sprintf("$base64$%s",
			base64.StdEncoding.EncodeToString([]byte(msg)),
		))
	}

	_, err = nutcracker.NewAPI(creds, nutcrackerServer).Post("/secrets/update", reqBody)
	if err != nil {
		alert["AlertContent"] = "Failed to update secret"
	} else {
		alert["AlertContent"] = fmt.Sprintf("Updated secret %s", reqBody["name"])
	}

	return
}

func addKey(r *http.Request, creds *nutcracker.Creds) (alert map[string]string, err error) {

	alert = make(map[string]string)
	reqBody := nutcracker.NewAPIReq()

	if !nameRe.MatchString(r.FormValue("name")) {
		alert["AlertContent"] = "Invalid name"
		return
	}

	reqBody.Set("name", strings.TrimSpace(r.FormValue("name")))

	if r.FormValue("admin") == "true" {
		reqBody["admin"] = true
	}

	resp, err := nutcracker.NewAPI(creds, nutcrackerServer).Post("/secrets/key", reqBody)
	if err != nil {
		alert["AlertContent"] = "Failed to create key"
		return
	}

	result := make(map[string]interface{})
	err = json.Unmarshal(resp, &result)
	if err != nil {
		alert["AlertContent"] = "Failed to read response"
		return
	}

	alert["AlertContent"] = fmt.Sprintf("Created key %s.\n\nsecret: %s", reqBody["name"], result["Key"])
	return
}
