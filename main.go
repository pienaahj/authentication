package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/pienaahj/authentication/conf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

var githubOauthConfig = &oauth2.Config{
	ClientID:     "538ea563d528f457bd46",
	ClientSecret: "5d600c8c314322e4fadb141e8ce270bd348478c6",
	Endpoint:     github.Endpoint,
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
	// You will typically use a db to hold the AuthCodeURLs for specific login attemps
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

// 		// ********************* check valid session ****************************

// 		//******************************* end check valid session ***************************************

// **************************************************************************************************
// **************************************************************************************************
