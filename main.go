package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
	email      string //email or username
	cookieName string //optional for future use
	password   []byte //bcrypted user password
	passW      string //unencrpted user password
}

// config for gitbub oauth2
var githubOauthConfig = &oauth2.Config{
	ClientID:     "538ea563d528f457bd46",
	ClientSecret: "5d600c8c314322e4fadb141e8ce270bd348478c6",
	Endpoint:     github.Endpoint,
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
var amazonOauthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.479f18b080cc4a20a8b9206834a7a596",
	ClientSecret: "bfdca5433cd5213bb306efc835032b277e410e9b4f0440b31b6063482d860d9c",
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth2/amazon/receive", // this is where amazon needs to return your token
	// note most servers will only allow http requests to localhost all others needs https
	Scopes: []string{"profile"},
}
var (
	sessionID uuid.UUID
	// create map to store sessions of UUID(sessionID) per email
	sessions = map[string]uuid.UUID{}
	email    string //temperary storage for user email
	msg      string //use as message field
	// Get a useDB instance
	myUser = userDB{}
	// create a state for oauth2 type uuid
	stateUUID uuid.UUID
	// create the oauth2 login map key: state uuid type string, value: expiration duration type time.Time
	amazonState = map[string]time.Time{}
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
	http.HandleFunc("/success", c.success)
	// handle the logout route
	http.HandleFunc("/logout", c.logout)
	// handle the amazon oauth login route POST
	http.HandleFunc("/oauth2/amazon/login", c.oauth2AmazonLogin)
	// handle the startOauthGithub route POST
	http.HandleFunc("/oauth2/github/login", c.oath2GithubLogin)
	// handle the completeGithubOauth route
	// http.HandleFunc("/oauth2/receive", c.completeGithubOauth)
	// handle the completeAmazonOauth route
	http.HandleFunc("/oauth2/amazon/receive", c.completeAmazonOauth)

	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handle the oath2GithubLogin page POST route - /aouth/gitbub/login
func (c Controller) oath2GithubLogin(w http.ResponseWriter, req *http.Request) {
	// You will typically use a db to hold the AuthCodeURLs for specific login attemps
	redirectURL := githubOauthConfig.AuthCodeURL("0000") //code&state gets put into the redirect url on github page
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

// handle the oauth2login page POST route - /oauth2/amazon/login
func (c Controller) oauth2AmazonLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		msg = url.QueryEscape("Your method was not POST")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// create the amazonState
	stateUUID, err := uuid.NewV4()
	if err != nil {
		msg = url.QueryEscape(err.Error())
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		fmt.Printf("Could not create uuid for amazon state: %v", err)
		return
	}
	state := stateUUID.String()
	amazonState[state] = time.Now().Add(time.Hour) // expire the state at 1 hour
	log.Printf("The amazon state: %v created\n with expiary time: %v\n", state, amazonState[state])
	redirectURL := amazonOauthConfig.AuthCodeURL(state)
	//code&state gets put into the redirect url on amazon page
	http.Redirect(w, req, redirectURL, http.StatusSeeOther)
}

// handle the root page GET route - /
func (c Controller) register(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Root page started")
	// get cookie back
	fmt.Printf("Email: %v\n", sessions[email])
	fmt.Println()
	// see if there is session
	if sessions[email] == uuid.Nil { // no session
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
	} else {
		// there is session
		cookie, err := req.Cookie(cookieName) // get the cookie back
		fmt.Printf("There is session, Cookie: %v\n", cookie)
		fmt.Println()
		if err != nil { //no session
			fmt.Printf("cannot retrieve cookie %v\n", cookie)
		}

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
		// // compare the stored uuid to the generated uuid from sID
		// ssID, err := uuid.FromString(sUUID.String())
		// if err != nil { // wrong sID
		// 	msg = url.QueryEscape(err.Error())
		// 	http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		// 	fmt.Printf("Could not parse UUID")
		// 	fmt.Println()
		// 	return
		// }
		// fmt.Println("UUID verified....")
		// // lookup the SessionID in map
		// if _, ok := sessions[ssID]; !ok {
		// 	fmt.Println("No valid session in root page, cannot find sessions map!")
		// 	msg = "" // no valid session
		// 	email = ""
		// } else {
		// 	fmt.Println("Valid session in root page.")
		// 	msg = ""
		// 	email = sID
		// }
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
	if myUser.email == email {
		msg = url.QueryEscape("You have not supplied a valid email/password ")
		http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
		return
	}
	// store email in myUser
	myUser.email = email

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
	http.Redirect(w, req, "/", http.StatusSeeOther)
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
	// create a session
	sessionID, err = uuid.NewV4()
	if err != nil {
		msg = url.QueryEscape("Internal server error occured.")
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
		return
	}
	sessions[email] = sessionID

	// get cookie back
	cookie, err := req.Cookie(cookieName)
	if err == nil { // cookie exists for this session
		cookie = &http.Cookie{} // clear the cookie
	}
	// re-create the cookie for session
	// create the token
	// JWT token
	token, err := createJWT(myUser.email)
	if err != nil {
		log.Printf("Error while verifying JWT token: %v\n", err)
		msg = url.QueryEscape("Internal server error occured.")
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
		return
	}
	// populate cookie
	cookie = &http.Cookie{
		Name:  cookieName,
		Value: token, //token
	}
	// set the cookie
	http.SetCookie(w, cookie)
	fmt.Printf("Password verified for: %v\n", myUser.email)
	fmt.Printf("Cookie set as: Name: %v Value: %v\n", cookie.Name, cookie.Value)
	fmt.Println()
	fmt.Println("email: ", sessions[myUser.email])
	fmt.Println()
	// display the login screen
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// handle the successful login  GET route - /success
func (c Controller) success(w http.ResponseWriter, req *http.Request) {
	// populate the template struct with empty values
	// retrieve the email if provided before
	msg = req.FormValue("msg")
	templateData := struct {
		Email string
		msg   string
	}{
		Email: myUser.email,
		msg:   msg,
	}
	c.tpl.ExecuteTemplate(w, "success.gohtml", templateData)
}

// handle the logout POST route - /login
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
	return
}

// **************************************** github complete *********************************************
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

// ************************************** amazon complete ************************************************
// handle the completeGithubOauth page GET route - /oauth2/amazon/receive
func (c Controller) completeAmazonOauth(w http.ResponseWriter, req *http.Request) {
	code := req.FormValue("code")
	stateReturned := req.FormValue("state")

	// check that the state is correct or stil valid if you have a timeout
	if rTime, ok := amazonState[stateReturned]; !ok {
		http.Error(w, "State is not correct!", http.StatusBadRequest)
		log.Printf("The amazon state is invalid!")
		return
	} else if rTime.Before(time.Now()) {
		http.Error(w, "State expired!", http.StatusBadRequest)
		log.Printf("The amazon state has expired! Time now: %v\n Expiry time for state: %v\n", time.Now(), rTime)
		return
	}

	// get the token back
	token, err := amazonOauthConfig.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, "Could not login", http.StatusInternalServerError)
		log.Printf("Could not get token from amazon, for code: %v\n", code)
		return
	}
	// the token received from amazon
	log.Printf("Amazon token: %v\n", token)

	// get the token source from token
	ts := amazonOauthConfig.TokenSource(req.Context(), token)
	log.Printf("Amazon token source: %v\n", ts)

	// get the http client from the token source you now have a client that is authenticated by the resource provider
	client := oauth2.NewClient(req.Context(), ts)
	fmt.Printf("Amazon client: %v\n", client)
	// amazon response
	// http://localhost:8080/oauth2/amazon/receive?code=ANvVzJPdqkyACgzMPFBM&scope=profile&state=a3b2ca7e-324a-476f-8f0f-5294a3e84008

	// make a graphql request to github to look up the viewer's id
	// construct the json query string (json keys without the values)
	// requestBody := strings.NewReader(`{"query":"query {viewer {id}}"}`)
	// // GraphQL query structure for github:
	// // { \
	// //	\"query\": \"query { viewer { login }}\" \
	// //  } \
	// resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	// if err != nil {
	// 	http.Error(w, "Cannot get user", http.StatusInternalServerError)
	// 	return
	// }
	// defer resp.Body.Close()

	// bs, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	http.Error(w, "Cannot read github information", http.StatusInternalServerError)
	// 	return
	// }
	// log.Println(string(bs)) //JSON response from github: {"data":{"viewer":{"id":"MDQ6VXNlcjYzMDUzNjU0"}}}

	// // create a instance of githubresponse
	// var gr = githubResponse{}
	// // unmarshall github response
	// err = json.NewDecoder(resp.Body).Decode(&gr)
	// if err != nil {
	// 	http.Error(w, "Github invalid response!", http.StatusInternalServerError)
	// 	return
	// }
	// // get github id
	// githubID := gr.Data.Viewer.ID
	// // store in db
	// userID, ok := githubConnections[githubID]
	// if !ok {
	// 	// new user create account
	// }
	// // log into account with userID and JWT
	// fmt.Println("userID: ", userID)
}
