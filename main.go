package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/pienaahj/authentication/conf"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

// NewController provides new controller for template processing
func NewController(t *template.Template) *Controller {
	return &Controller{t}
}

func main() {
	// Get a template controller value.
	c := NewController(conf.TPL)

	// handle the root route
	http.HandleFunc("/", c.index)
	// handle the startOauthGithub route
	http.HandleFunc("/oauth/github", c.startGithubOauth)

	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handle the index page GET route - /
func (c Controller) index(w http.ResponseWriter, req *http.Request) {

}

// handle the startGithubOauth page POST route - /
func (c Controller) startGithubOauth(w http.ResponseWriter, req *http.Request) {

}

// 		// ********************* check valid session ****************************

// 		//******************************* end check valid session ***************************************

// **************************************************************************************************
// **************************************************************************************************
