package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pienaahj/authentication/conf"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/github"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

//create the key
const (
	mySigningKey = "ourkey 1234"
	cookieName   = "sessionID"
)

// userDB struct for users data
type userDB struct {
	name       string // user's name
	age        int    //user's age
	terms      bool   // terms of service accepted
	email      string // email or username
	cookieName string // optional for future use
	password   []byte // bcrypted user password
	passW      string // unencrpted user password
}

// config for gitbub oauth2
var githubOauthConfig = &oauth2.Config{
	ClientID:     "538ea563d528f457bd46",
	ClientSecret: "5d600c8c314322e4fadb141e8ce270bd348478c6",
	Endpoint:     github.Endpoint,
}

// githibResponse struct
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

// amazonResponse struct
type amazonResponse struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	// PostalCode string `json:"postal_code"`
}

// db for github connections key:github ID value:user ID
// var githubConnections map[string]string

// db for oauthConnections key:<provider ID> value:user ID(email)
var oauthConnections = map[string]string{}

// config for gitbub oauth2
var amazonOauthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.479f18b080cc4a20a8b9206834a7a596",
	ClientSecret: "bfdca5433cd5213bb306efc835032b277e410e9b4f0440b31b6063482d860d9c",
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth2/amazon/receive", // this is where amazon needs to return your token
	// note most servers will only allow http requests to localhost all others needs https
	Scopes: []string{"profile"},
}
var (
	// create a sessions id type uuid
	sessionID uuid.UUID
	// create map to store sessions key:email values: UUID(sessionID)
	sessions = map[string]uuid.UUID{}
	email    string //temperary storage for user email
	name     string //temperary storage for user name
	msg      string //use as message field
	sToken   string //signed JWT token
	// Get a useDB instance
	myUser = userDB{}
	// create a state for oauth2 type uuid
	stateUUID uuid.UUID
	// create the oauth2 login map key: state uuid type string, value: expiration duration type time.Time
	oauth2State = map[string]time.Time{}
)

// NewController provides new controller for template processing
func NewController(t *template.Template) *Controller {
	return &Controller{t}
}

func main() {
	// Get a template controller value.
	c := NewController(conf.TPL)

	// handle the root route
	http.HandleFunc("/", c.register)
	// handle the register route
	http.HandleFunc("/process", c.processForm)
	// handle the login route
	http.HandleFunc("/login", c.login)
	//hangle the successful login route
	// http.HandleFunc("/success", c.success)
	// handle the logout route
	http.HandleFunc("/logout", c.logout)
	// handle the amazon oauth login route POST
	http.HandleFunc("/oauth2/amazon/login", c.oauth2AmazonLogin)
	// handle the startOauthGithub route POST
	http.HandleFunc("/oauth2/github/login", c.oath2GithubLogin)
	// handle the completeGithubOauth route GET
	http.HandleFunc("/oauth2/github/receive", c.completeGithubOauth)
	// handle the completeAmazonOauth route GET
	http.HandleFunc("/oauth2/amazon/receive", c.completeAmazonOauth)
	// handle partial-register route GET
	http.HandleFunc("/partial-register", c.partialRegister)
	// handle oauth/register route POST
	http.HandleFunc("/oauth/register", c.oauth2Register)

	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handle the oath2GithubLogin page POST route - /aouth/gitbub/login
func (c Controller) oath2GithubLogin(w http.ResponseWriter, req *http.Request) {
	// You will typically use a db to hold the AuthCodeURLs for specific login attemps
	if req.Method != http.MethodPost {
		msg = url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// create the oauth2State
	stateUUID, err := uuid.NewV4()
	if err != nil {
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		fmt.Printf("Could not create uuid for Github state: %v", err)
		return
	}
	state := stateUUID.String()
	oauth2State[state] = time.Now().Add(time.Hour) // expire the state at 1 hour
	log.Printf("The Github state: %v created\n with expiary time: %v\n", state, oauth2State[state])
	redirectURL := githubOauthConfig.AuthCodeURL(state)
	//code&state gets put into the redirect url on github page
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

// handle the oauth2login page POST route - /oauth2/amazon/login
func (c Controller) oauth2AmazonLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		msg = url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// create the oauth2State
	stateUUID, err := uuid.NewV4()
	if err != nil {
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		fmt.Printf("Could not create uuid for amazon state: %v", err)
		return
	}
	state := stateUUID.String()
	oauth2State[state] = time.Now().Add(time.Hour) // expire the state at 1 hour
	log.Printf("The amazon state: %v created\n with expiary time: %v\n", state, oauth2State[state])
	redirectURL := amazonOauthConfig.AuthCodeURL(state)
	//code&state gets put into the redirect url on amazon page
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

// handle the oauth2Register page POST route - /oauth/register
func (c Controller) oauth2Register(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		msg = url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/partial-register?msg= "+msg, http.StatusSeeOther)
		return
	}
	email = req.FormValue("email")
	if email == "" {
		msg = url.QueryEscape("Your email cannot be empty")
		http.Redirect(w, req, "/partial-register?msg= "+msg, http.StatusSeeOther)
		return
	}
	// check if email exist
	if myUser.email == email {
		msg = url.QueryEscape("You have not supplied a valid email/password ")
		http.Redirect(w, req, "/partial-register?msg= "+msg, http.StatusSeeOther)
		return
	}

	// store email in myUser
	myUser.email = email
	// store name, age and terms in myUser
	myUser.name = req.FormValue("name")
	ageT, err := strconv.Atoi(req.FormValue("age"))
	if err != nil {
		msg = url.QueryEscape("You have not supplied a valid age ")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	myUser.age = ageT
	// check if user has not accepted the terms and store it
	if len(req.Form["terms"]) < 1 {
		msg = url.QueryEscape("You have not accepted the terms and conditions!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	terms := req.Form["terms"][0]
	fmt.Println("terms: ", terms)
	myUser.terms = true
	// retrieve the signed userid
	githubID := req.FormValue("sid")

	// store connection with
	log.Printf("storing user: %v\n in oauthSession with Github ID: %s\n", sToken, githubID)
	oauthConnections[githubID] = myUser.email
	// log into account with userID and JWT
	fmt.Println("loggin in userID: ", githubID)
	fmt.Println()
	err = createSession(w, myUser.email)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured: " + err.Error())
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
	}
	fmt.Println("****************************** - User logged in with Github oauth2 - **************************")
	fmt.Println()
	// ****************************************************************************************************************

	// ****************************************************************************************************************
	fmt.Println()
	// display the login screen
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// handle partialRegister GET route - /partial-register
func (c Controller) partialRegister(w http.ResponseWriter, req *http.Request) {

	// populate the template struct with values
	templateData := struct {
		Email string
		SID   string
		Name  string
		Msg   string
	}{
		Email: email,  // pre-populate retrieved email
		SID:   sToken, // push in the signed userID
		Name:  name,   // pre-populate retrieved name
		Msg:   msg,
	}
	c.tpl.ExecuteTemplate(w, "oauth2Login.gohtml", templateData)
}

// handle the root page GET route - /
func (c Controller) register(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Root page started")
	fmt.Printf("Email: %v\n", myUser.email)
	fmt.Println()
	// see if there is session
	if sessions[myUser.email] == uuid.Nil { // no session
		// clear the cookie
		cookie := &http.Cookie{}
		email = ""
		msg = req.FormValue("msg")
		fmt.Println("msg: ", msg)
		http.SetCookie(w, cookie)
		fmt.Printf("No session, Cookie cleared: %v\n", cookie)
		fmt.Println()
		// populate the template struct with values
		templateData := struct {
			Email string
			Msg   string
		}{
			Email: email,
			Msg:   msg,
		}
		c.tpl.ExecuteTemplate(w, "landing.gohtml", templateData)
		return
	}
	// there is session
	cookie, err := req.Cookie(cookieName) // get the cookie back

	if err != nil { //no session
		fmt.Printf("There is session, but cannot retrieve cookie %v\n", cookie)
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	fmt.Printf("There is session, Cookie: %v\n", cookie)
	fmt.Println()

	// ********************* check valid session ****************************
	fmt.Println("Checkking valid session......")
	fmt.Println()
	// retrieve the token
	oldToken := cookie.Value
	fmt.Printf("Cookie retrieved as:\n Name: %v\n Value: %v\n", cookie.Name, cookie.Value)
	fmt.Println()

	// JWT parseJWT token
	sID, err := parseJWT(oldToken)
	if err != nil { // error parsing token - hacked!
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		fmt.Printf("Could not parse token: %v", oldToken)
		fmt.Println()
		return
	}
	fmt.Println("Token verified....")
	// lookup uuid from sID
	fmt.Printf("Using %v as sID\n", sID)
	// look the sID up in session map
	sUUID, ok := sessions[sID]
	if !ok {
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		fmt.Printf("Invalid session for: %v", sID)
		fmt.Println()
		return
	}

	fmt.Println("UUID verified as : ", sUUID)
	fmt.Println("Valid session in root page.")
	msg = ""
	email = sID
	//******************************* end check valid session ***************************************

	// populate the template struct with values
	templateData := struct {
		Email string
		Msg   string
	}{
		Email: myUser.email,
		Msg:   msg,
	}
	c.tpl.ExecuteTemplate(w, "landing.gohtml", templateData)

}

// handle the process POST route - /process - registered
func (c Controller) processForm(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		msg = url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	email = req.FormValue("email")
	if email == "" {
		msg = url.QueryEscape("Your email cannot be empty")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// check if email exist
	// if myUser.email == email {
	// 	msg = url.QueryEscape("You have not supplied a valid email/password ")
	// 	http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
	// 	return
	// }
	// store email in myUser
	myUser.email = email
	// store name, age and terms in myUser
	myUser.name = req.FormValue("name")
	ageT, err := strconv.Atoi(req.FormValue("age"))
	if err != nil {
		msg = url.QueryEscape("You have not supplied a valid age ")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	myUser.age = ageT

	// check if user has not accepted the terms
	if len(req.Form["terms"]) < 1 {
		msg = url.QueryEscape("You have not accepted the terms and conditions!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	terms := req.Form["terms"][0]
	fmt.Println("terms: ", terms)
	myUser.terms = true
	// if terms != "on" {
	// 	msg = url.QueryEscape("You have not accepted the terms and conditions!")
	// 	http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
	// 	return
	// }
	// note that you need to be as vague as possible with the messages here
	password := req.FormValue("password")
	if password == "" {
		msg := url.QueryEscape("You have not supplied a valid email/password ")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// store login credentials in localStorage map
	// encrypt password
	passW, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured.")
		http.Error(w, msg, http.StatusInternalServerError) // will display on separate page with only the error
		return
	}
	myUser.password = passW
	// store unencrypted password
	myUser.passW = password
	fmt.Println("Leaving register page - returning to root")
	msg := url.QueryEscape("You are registered.")
	http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
}

// handle the login POST route - /login
func (c Controller) login(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		msg := url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	email = req.FormValue("email")
	if email == "" {
		msg := url.QueryEscape("Your email cannot be empty")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}

	password := req.FormValue("password")
	if password == "" {
		msg := url.QueryEscape("You have not supplied a valid email/password ")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// verify login credentials in myUser
	// retrieve password
	if myUser.email != email { // wrong email
		msg := url.QueryEscape("You need to register first!!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// verify password
	err := bcrypt.CompareHashAndPassword(myUser.password, []byte(password))
	if err != nil {
		msg := url.QueryEscape("Wrong password")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		// if there was a session clear it
		sessions[myUser.email] = uuid.Nil
		return
	}

	// log into account with userID and JWT
	err = createSession(w, myUser.email)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured: " + err.Error())
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
	}

	// display the login screen
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// handle the logout POST route - /logout
func (c Controller) logout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		msg := url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}

	// get the cookie back
	cookie, err := req.Cookie(cookieName)
	if err != nil { // cookie does not exists for this session, clear the cookie
		cookie = &http.Cookie{
			Name:  cookieName,
			Value: "",
		}
	}

	// get the session id
	sID, err := parseJWT(cookie.Value)
	if err != nil {
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		fmt.Printf("Could not parse token in logout: %v", cookie.Value)
		fmt.Println()
		return
	}

	user := myUser.email
	// delete the session
	delete(sessions, sID)

	// set the msg
	msg := fmt.Sprintf("%s logged out!", user)
	msg = url.QueryEscape(msg)

	// delete the cookie
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)

	// display the login screen
	http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
}

// **************************************** github receive *********************************************
// handle the completeGithubOauth page GET route - /oauth2/github/receive
func (c Controller) completeGithubOauth(w http.ResponseWriter, req *http.Request) {
	code := req.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("No code returned!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		log.Printf("No code returned from Github.\n")
		return
	}
	stateReturned := req.FormValue("state")
	if stateReturned == "" {
		msg := url.QueryEscape("No code returned!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		log.Printf("No code returned from Github\n")
		return
	}

	// check that the state is correct or still valid if you have a timeout
	if rTime, ok := oauth2State[stateReturned]; !ok {
		http.Error(w, "State is not correct!", http.StatusBadRequest)
		log.Printf("The Github state is invalid!")
		return
	} else if rTime.Before(time.Now()) {
		http.Error(w, "State expired!", http.StatusBadRequest)
		log.Printf("The Github state has expired! Time now: %v\n Expiry time for state: %v\n", time.Now(), rTime)
		return
	}
	// get the token back
	token, err := githubOauthConfig.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, "Could not login", http.StatusInternalServerError)
		log.Printf("Could not get token from Github, for code: %v\n", code)
		return
	}
	// the token received from Github
	log.Printf("Github token type: %v\n", token.TokenType)

	// get the token source from token
	ts := githubOauthConfig.TokenSource(req.Context(), token)

	// get the http client from the token source you now have a client that is authenticated by the resource provider
	client := oauth2.NewClient(req.Context(), ts)
	fmt.Printf("Github client: %v\n", client)
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
		http.Error(w, "Cannot read Github information", http.StatusInternalServerError)
		return
	}
	log.Println(string(bs)) //JSON response from github: {"data":{"viewer":{"id":"MDQ6VXNlcjYzMDUzNjU0"}}}
	log.Printf("Json response from Github: %s\n", string(bs))
	// create a instance of githubresponse
	var gr = githubResponse{}
	// unmarshall github response
	err = json.Unmarshal(bs, &gr)
	if err != nil {
		http.Error(w, "Github invalid response!", http.StatusInternalServerError)
		log.Printf("Github invalid response! %v\n", err)
		return
	}

	// get github id
	githubID := gr.Data.Viewer.ID
	// make a signed userID by signing the returned userid
	sToken, err = createJWT(githubID)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured.")
		http.Error(w, msg, http.StatusInternalServerError) // will display on separate page with only the error
		return
	}
	// get Github id & store in db

	// check if there is a connection for this userID
	_, ok := oauthConnections[sToken]
	if !ok {
		// new user create account
		// create a registered user from oauth2 authentication
		// ******************************************** create a registered user ******************************************
		http.Redirect(w, req, "/partial-register", http.StatusSeeOther)
		// ****************************************************************************************************************

	}
	// log into account with userID and JWT
	fmt.Println("loggin in userID: ", sToken)
	fmt.Println()
	err = createSession(w, myUser.email)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured: " + err.Error())
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
	}
	fmt.Println("****************************** - User logged in with Github oauth2 - **************************")
	fmt.Println()
	// ****************************************************************************************************************

	// ****************************************************************************************************************

	// display the login screen
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// **************************************** github complete *********************************************

// ************************************** amazon receive ************************************************
// handle the completeGithubOauth page GET route - /oauth2/amazon/receive
func (c Controller) completeAmazonOauth(w http.ResponseWriter, req *http.Request) {
	code := req.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("No code returned!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		log.Printf("No code returned from Amazon\n")
		return
	}
	stateReturned := req.FormValue("state")
	if stateReturned == "" {
		msg := url.QueryEscape("No code returned!")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		log.Printf("No code returned from Amazon\n")
		return
	}

	// check that the state is correct or still valid if you have a timeout
	if rTime, ok := oauth2State[stateReturned]; !ok {
		http.Error(w, "State is not correct!", http.StatusBadRequest)
		log.Printf("The amazon state is invalid!")
		return
	} else if rTime.Before(time.Now()) {
		http.Error(w, "State expired!", http.StatusBadRequest)
		log.Printf("The amazon state has expired! Time now: %v\n Expiry time for state: %v\n", time.Now(), rTime)
		return
	}

	// exchange the code for a token(access token - which can expire) by accessing the TokenURL in the config
	// browser never sees token, only code
	token, err := amazonOauthConfig.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, "Could not login", http.StatusInternalServerError)
		log.Printf("Could not get token from amazon, for code: %v\n", code)
		return
	}
	// the token received from amazon
	log.Printf("Amazon token type: %v\n", token.TokenType)

	// get the token source from token - this has both the current token and the refresh token - if it expires will auto refresh
	ts := amazonOauthConfig.TokenSource(req.Context(), token)
	log.Printf("Amazon token source: %v\n", ts)

	// get the http client from the token source you now have a client that is authenticated by the resource provider
	// with a client you can do get request to find the scope items - like user-id
	client := oauth2.NewClient(req.Context(), ts)
	fmt.Printf("Amazon client: %v\n", client)
	// amazon response
	// http://localhost:8080/oauth2/amazon/receive?code=ANvVzJPdqkyACgzMPFBM&scope=profile&state=a3b2ca7e-324a-476f-8f0f-5294a3e84008

	resp, err := client.Get("https://api.amazon.com/user/profile")
	if err != nil {
		http.Error(w, "Cannot get user", http.StatusInternalServerError)
		log.Printf("Amazon response error occured! %v\n", err)
		return
	}
	// it is the caller's responsibility to close the resp.body
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Cannot read Amazon information", http.StatusInternalServerError)
		log.Printf("Cannot read from Amazon response body! %v\n", string(bs))
		return
	}

	// check the resp status codes for errors
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		http.Error(w, "Amazon response error occured", http.StatusInternalServerError)
		log.Printf("Amazon response status error occured! %v\n", string(bs))
		return
	}

	log.Printf("Json response from Amazon: %s\n", string(bs))
	//JSON response from amazon:
	// {"user_id":"amzn1.account.AGLMAOQ2KNQ3PHKHG00000","name":"HJ Pienaar","email":"pienaahj@gmail.com"}

	// // create a instance of amazonResponse
	var gr = amazonResponse{}
	// unmarshall amazon response
	// err = json.NewDecoder(resp.Body).Decode(&gr)
	err = json.Unmarshal(bs, &gr)
	if err != nil {
		http.Error(w, "Amazon invalid response!", http.StatusInternalServerError)
		log.Printf("Amazon invalid response! %v\n", err)
		return
	}
	log.Printf("User from amazon: %v\n", gr)
	// get Amazon id
	amazonID := gr.UserID
	// make a signed userID by signing the returned userid
	sToken, err = createJWT(amazonID)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured.")
		http.Error(w, msg, http.StatusInternalServerError) // will display on separate page with only the error
		return
	}
	// get amazon id & store in db
	_, ok := oauthConnections[sToken]
	if !ok { // user does not exist
		// log.Printf("Creating new Amazon user in connections, User id: %v...\n", gr.UserID)
		http.Redirect(w, req, "/partial-register", http.StatusSeeOther)

	}
	// log into account with userID and JWT
	fmt.Println("loggin in userID: ", sToken)
	fmt.Println()
	err = createSession(w, myUser.email)
	if err != nil {
		msg = url.QueryEscape("Internal server error occured: " + err.Error())
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
	}
	fmt.Println("****************************** - User logged in with Amazon oauth2 - **************************")
	fmt.Println()

	// save the Amazon email in email
	email = gr.Email
	// save the Amazon name
	name = gr.Name
	// ****************************************************************************************************************

	// ****************************************************************************************************************
	// display the login screen
	http.Redirect(w, req, "/", http.StatusSeeOther)
	return
}

// ************************************** amazon complete ************************************************

// createSession creates an user session
func createSession(w http.ResponseWriter, email string) error {
	// create a session with new uuid
	sessionID, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("could not create seesion id: %w", err)
	}
	// create session for user in sessions map
	sessions[email] = sessionID

	// re-create the cookie for session
	// create the JWT token
	token, err := createJWT(email)
	if err != nil {
		log.Printf("Error while verifying JWT token: %v\n", err)
		return fmt.Errorf("could not create seesion id: %w", err)
	}
	// populate cookie
	cookie := &http.Cookie{
		Name:  cookieName,
		Value: token, // token
		Path:  "/",   // THIS IS ESSECIAL FOR OAUTH2 TO WORK!!!!! A COOKIE IS SCOPED!THIS ONE IS ON AMAZON/RECIEVE
		// SO YOU NEED TO RESCOPE IT TO "/"
		// SameSite: http.SameSiteNoneMode,
		// Secure:   false,
	}
	// set the cookie
	http.SetCookie(w, cookie)
	fmt.Printf("Password verified for: %v\n", email)
	fmt.Printf("Cookie set as: Name: %v\n Value: %v\n", cookie.Name, cookie.Value)
	fmt.Println()
	return nil
}
