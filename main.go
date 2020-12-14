package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pienaahj/authentication/conf"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

//MyCustomClaims create type
type MyCustomClaims struct {
	Data string `json:"myclaimsfield"`
	jwt.StandardClaims
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

var (
	sessionID uuid.UUID
	// create map to store sessions of UUID(sessionID) per email
	sessions = map[string]uuid.UUID{}
	email    string //temperary storage for user email
	msg      string //use as message field
	// Get a useDB instance
	myUser = userDB{}
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

	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// createJWT uses input data - string and returns an JWT - string
func createJWT(sID string) (string, error) {
	// this is tricky - embeds
	claims := MyCustomClaims{
		sID,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(), // Unix() type int64
			Issuer:    "me",
		},
	}
	// create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // hmac sha256 signing method
	// sign the token with your key
	ss, err := token.SignedString([]byte(mySigningKey)) // hmac requires a []byte type as key
	if err != nil {
		return "", fmt.Errorf("Could not sign token in SignedString: %w", err)
	}
	return ss, nil
}

// parseJWT parses the JWT token from a JWT token and returns the sessionID
func parseJWT(t string) (string, error) {
	// check signature - this is weird!! you don't need an instance just a type of MyCustomClaims
	// this firstly uses the token(in the callback function) and then verifies it in the same step.
	verifiedToken, err := jwt.ParseWithClaims(t, &MyCustomClaims{}, func(unverifiedToken *jwt.Token) (interface{}, error) {
		// according to jwt advisory you need to check if your signing method remained the same in callback.
		// the signing method are carried inside the unverified token. The Mothod filed of the token type carries Alg() from
		// the SigningMethod used.
		if unverifiedToken.Method.Alg() != jwt.SigningMethodHS256.Alg() { // check that the signing method used is the one received
			return nil, errors.New("someone tried changing the signing method")
		}
		return []byte(mySigningKey), nil
	})

	// Is the token valid?  It is populated when you Parse/Verify a token - only checks if the claims has not expired
	if err == nil && verifiedToken.Valid { //there was no error and the token is valid
		// need to assert VerifiedToken of *MyCustomeClaims type!! You know what you passed in when created.
		// Claims type interface with valid method only
		claims := verifiedToken.Claims.(*MyCustomClaims)
		return claims.Data, nil
	} // important to check the error first nill pointer value see running video
	return "", errors.New("error while verifying token")
}

// handle the root page GET route - /
func (c Controller) register(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Root page started")
	//get cookie back
	fmt.Printf("Email: %v\n", sessions[email])
	fmt.Println()
	//see if there is session
	if sessions[email] == uuid.Nil { //no session
		//clear the cookie
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
		cookie, err := req.Cookie(cookieName) //get the cookie back
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
