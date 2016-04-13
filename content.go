package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

var re *regexp.Regexp

func init() {
	re = regexp.MustCompile(`\.([a-zA-Z0-9]+)$`)
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
		if re.FindString(filePath) == ".svg" {
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
			_, err := newAPI(nil).Get("/seal")
			if err != nil {
				log.Error(err)
				http.Error(w, "Nutcracker request error", 500)
				return
			}

		case len(master) > 1:
			_, err := newAPI(&Creds{
				Username: "master",
				Password: master,
			}).Get("/unseal")
			if err != nil {
				log.Error(err)
				http.Error(w, "Nutcracker request error", 500)
				return
			}
		}
	}

	m := metrics.latest()
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

	if r.Method == "POST" {

		search := r.FormValue("search")
		url := "/secrets/list/keys/" + search
		tableHeader, tableContent, err = keyTable(url, creds)
		tableTitle = fmt.Sprintf("Keys with access to %s secret:", search)

	} else {

		url := "/secrets/list/secrets"
		tableHeader, tableContent, err = secretTable(url, creds)
		tableTitle = "All secrets"

	}

	m := metrics.latest()
	alert := unsealAlert(m)

	tmpl.New("body").ParseFiles(htmlDir + "/content/table.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			"PageLink":       "/secrets",
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
		tmplVars["Body"].(map[string]interface{})["VaultSealed"] = true
	} else {
		tmplVars["Body"].(map[string]interface{})["VaultUnsealed"] = true
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

	if r.Method == "POST" {

		search := r.FormValue("search")
		url := "/secrets/list/secrets/" + search
		tableHeader, tableContent, err = secretTable(url, creds)
		tableTitle = fmt.Sprintf("Secrets readable by %s key:", search)

	} else {

		url := "/secrets/list/keys"
		tableHeader, tableContent, err = keyTable(url, creds)
		tableTitle = "All keys"

	}

	m := metrics.latest()
	alert := unsealAlert(m)

	tmpl.New("body").ParseFiles(htmlDir + "/content/table.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			"PageLink":       "/keys",
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
		tmplVars["Body"].(map[string]interface{})["VaultSealed"] = true
	} else {
		tmplVars["Body"].(map[string]interface{})["VaultUnsealed"] = true
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
	}

	m := metrics.latest()
	alert := unsealAlert(m)

	tmpl.New("body").ParseFiles(htmlDir + "/content/admin.html")

	tmplVars := map[string]interface{}{
		"Nav": navVars(r),
		"Body": map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		},
	}

	if alert != nil {
		tmplVars["Alert"] = alert
		tmplVars["Body"].(map[string]interface{})["VaultSealed"] = true
	} else {
		tmplVars["Body"].(map[string]interface{})["VaultUnsealed"] = true
	}

	err = tmpl.ExecuteTemplate(w, "main.html", tmplVars)
	if err != nil {
		log.Error(err)
		http.Error(w, "Template rendering error", 500)
	}
}

func unsealAlert(m MetricVal) map[string]string {
	if m.Sealed {
		return map[string]string{
			"AlertContent": "Vault is sealed, please unseal before making changes",
		}
	}
	return nil
}

func secretTable(url string, c *Creds) (tableHeader []string, tableContent map[string][]interface{}, err error) {
	data, err := newAPI(c).Get(url)
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

func keyTable(url string, c *Creds) (tableHeader []string, tableContent map[string][]interface{}, err error) {
	data, err := newAPI(c).Get(url)
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
