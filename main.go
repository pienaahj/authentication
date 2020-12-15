package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/pienaahj/authentication/conf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

// GithibResponse struct
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json: "id"`
		} `json:"viewer"`
	} `json:"data"`
}

// db for github connections key:github ID value:user ID
var githubConnections map[string]string

// config for gitbub oauth2
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
	// handle the completeGithubOauth route
	http.HandleFunc("/oauth2/receive", c.completeGithubOauth)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handle the index page GET route - /
func (c Controller) index(w http.ResponseWriter, req *http.Request) {
	c.tpl.ExecuteTemplate(w, "index.gohtml", nil)
}

// handle the startGithubOauth page POST route - /
func (c Controller) startGithubOauth(w http.ResponseWriter, req *http.Request) {
	// You will typically use a db to hold the AuthCodeURLs for specific login attemps
	redirectURL := githubOauthConfig.AuthCodeURL("0000") //code&state gets put into the redirect url on github page
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

// handle the completeGithubOauth page GET route - /
func (c Controller) completeGithubOauth(w http.ResponseWriter, req *http.Request) {
	code := req.FormValue("code")
	state := req.FormValue("state")

	// check that the state is correct or stil valid if you have a timeout
	if state != "0000" {
		http.Error(w, "State is not correct!", http.StatusBadRequest)
		return
	}
	// get the token back
	token, err := githubOauthConfig.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, "Could not login", http.StatusInternalServerError)
		return
	}

	// get the token source from token
	ts := githubOauthConfig.TokenSource(req.Context(), token)

	// get the http client from the token source you now have a client that is authenticated by the resource provider
	client := oauth2.NewClient(req.Context(), ts)

	// make a graphql request to github to look up the viewer's id
	// construct the json query string (json keys without the values)
	requestBody := strings.NewReader(`{"query":"query {viewer {id}}"}`)
	// GraphQL query structure for github:
	// { \
	//	\"query\": \"query { viewer { login }}\" \
	//  } \
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Cannot get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Cannot read github information", http.StatusInternalServerError)
		return
	}
	log.Println(string(bs)) //JSON response from github: {"data":{"viewer":{"id":"MDQ6VXNlcjYzMDUzNjU0"}}}

	// create a instance of githubresponse
	var gr = githubResponse{}
	// unmarshall github response
	err = json.NewDecoder(resp.Body).Decode(&gr)
	if err != nil {
		http.Error(w, "Github invalid response!", http.StatusInternalServerError)
		return
	}
	// get github id
	githubID := gr.Data.Viewer.ID
	// store in db
	userID, ok := githubConnections[githubID]
	if !ok {
		// new user create account
	}
	// log into account with userID and JWT
	fmt.Println("userID: ", userID)
}

// 		// ********************* check valid session ****************************

// 		//******************************* end check valid session ***************************************

// **************************************************************************************************
// **************************************************************************************************
