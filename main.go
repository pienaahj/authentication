package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pienaahj/authentication/conf"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

//MyCustomClaims create type
type MyCustomClaims struct {
	Data string `json:"myclaimsfield"`
	jwt.StandardClaims
}

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

//create the key
const (
	mySigningKey = "ourkey 1234"
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
	// create map to store sessions of UUID per email
	session = map[uuid.UUID]string{}
	email   string //temperary storage for user email
	msg     string //use as message field
	// Get a useDB instance
	myUser = userDB{}
)

// NewController provides new controller for template processing
func NewController(t *template.Template) *Controller {
	return &Controller{t}
}

// makeCookieName removes the '@' from cookie name and replace it with '_' returns a string
func makeCookieName(s string) string {
	return strings.Replace(s, "@", "_", 1)
}

// getEmail gets the email as string from cookie name aand replace '_' with '@' returns a string
func getEmail(s string) string {
	return strings.Replace(s, "_", "@", 1)
}

// find email in session from uuid
func findUUID(uid string) uuid.UUID {
	var tuid uuid.UUID
	for k, v := range session {
		if v == uid {
			tuid = k
		}
	}
	return tuid
}
func main() {
	// Get a template controller value.
	c := NewController(conf.TPL)

	// http.HandleFunc("/", createTestCookie)
	//handle the register route
	// http.HandleFunc("/submit", submit)
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

//getCode uses input data - string and returns an HAMC - string
func getCode(data string) string {
	//create the hmac hash
	h := hmac.New(sha256.New, []byte(mySigningKey))
	//write the data passed in to the hash
	io.WriteString(h, data)
	//convert the hash to a string and return it
	return fmt.Sprintf("%x", h.Sum(nil))
}

//create an HMAC token
func getHMAC(input string) string {
	//create the hmac hash
	h := hmac.New(sha256.New, []byte(mySigningKey))
	//write the data passed in to the hash
	io.WriteString(h, input)
	//convert the hash to a string and return it
	return fmt.Sprintf("%x", h.Sum(nil))
}

//createToken creates a HMAC token from sessionID and retruns signature + "|" + sessionID
func createToken(sID string) string {
	//get the HMAC of the sessionID
	signature := getHMAC(sID)
	//combine the sessionID and signature
	return signature + "|" + sID
}

//parseToken parses the HMAC token from a token and retruns the sessionID
func parseToken(t string) (string, error) {
	//split the token into signature and sessionID
	sX := strings.SplitN(t, "|", 2) //only allows tor 2 indexes, safer
	if len(sX) != 2 {
		return "", errors.New("not hacked, nice try")
	}
	rSignature := sX[0]
	sID := sX[1]
	//verify the token
	cSignature := createToken(sID)
	cSignature = strings.Split(cSignature, "|")[0] //split the token out
	if !hmac.Equal([]byte(rSignature), []byte(cSignature)) {
		fmt.Printf("hmac's not equal: \nrSignature :%v\n cSignature : %v\n ", rSignature, cSignature)
		return "", errors.New("not hacked, nice try")
	}
	return sID, nil
}

//getJWT uses input data - string and returns an JWT - string
func getJWT(data string) (string, error) {
	claims := MyCustomClaims{
		data,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(), //Unix() type int64
			Issuer:    "me",
		},
	}
	//create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) //hmac sha256 signing method
	//sign the token with your key
	ss, err := token.SignedString([]byte(mySigningKey)) //hmac requires a []byte type as key
	if err != nil {
		return "", fmt.Errorf("Could not sign token in SignedString: %w", err)
	}
	return ss, nil
}

//handle the root page GET route - /
func (c Controller) register(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Root page started")
	//get cookie back
	fmt.Printf("Email: %v\n", session[sessionID])
	fmt.Println()
	//see if there is session
	if session[sessionID] == "" { //no session
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
		// cookieTitle := makeCookieName(email)   //get a cookie name
		cookie, err := req.Cookie(myUser.cookieName) //get the cookie back
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
		sID, err := parseToken(oldToken)
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
		sUUID := findUUID(sID)
		// compare the stored uuid to the sID
		ssID, err := uuid.FromString(sUUID.String())
		if err != nil { // wrong sID
			msg = url.QueryEscape(err.Error())
			http.Redirect(w, req, "/?msg= "+msg, http.StatusSeeOther)
			fmt.Printf("Could not parse UUID")
			fmt.Println()
			return
		}
		fmt.Println("UUID verified....")
		// lookup the SessionID in map
		if _, ok := session[ssID]; !ok {
			fmt.Println("No valid session in root page, cannot find session map!")
			msg = "" // no valid session
			email = ""
		} else {
			fmt.Println("Valid session in root page.")
			msg = ""
			email = sID
		}

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
	// generate the cookie name
	myUser.cookieName = makeCookieName(email)

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
		session[sessionID] = ""
		return
	}
	// create a session
	sessionID, err = uuid.NewV4()
	if err != nil {
		msg = url.QueryEscape("Internal server error occured.")
		http.Error(w, msg, http.StatusInternalServerError) //will display on separate page with only the error
		return
	}
	session[sessionID] = makeCookieName(email)

	// get cookie back
	cookie, err := req.Cookie(session[sessionID])
	if err == nil { // cookie exists for this session
		cookie = &http.Cookie{} // clear the cookie
	}
	// re-create the cookie for session
	// create the token
	token := createToken(session[sessionID])
	// populate cookie
	cookie = &http.Cookie{
		Name:  session[sessionID], //email
		Value: token,              //token
	}
	// set the cookie
	http.SetCookie(w, cookie)
	fmt.Printf("Password verified for: %v\n", myUser.email)
	fmt.Printf("Cookie set as: Name: %v Value: %v\n", cookie.Name, cookie.Value)
	fmt.Println()
	fmt.Println("email: ", session[sessionID])
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
		Email: session[sessionID],
		msg:   msg,
	}
	c.tpl.ExecuteTemplate(w, "success.gohtml", templateData)
}

// **************************************************************************************************
// **************************************************************************************************

//handle the root route - create the cookie - test if cookie is the same as created - then logged in
func createTestCookie(w http.ResponseWriter, req *http.Request) {
	//get cookie back
	cookie, err := req.Cookie("session-id")
	if err != nil {
		cookie = &http.Cookie{}
	}
	//setting message
	message := "Not logged in!..."
	isEqual := true
	// if there is a cookie process it
	if len(cookie.Value) != 0 {
		fmt.Println("*******************evaluating cookie****************************")
		fmt.Println("Cookie: ", cookie.Value)
		fmt.Println()

		//get the email from cookie
		// email := strings.SplitAfter(cookie.Value, "|")[1]
		// fmt.Println("Cookie email: ", strings.Split(cookie.Value, "|")[1])
		// fmt.Println()

		//get the hmac from cookie
		// returnCode := strings.Split(cookie.Value, "|")[0]
		// fmt.Println("Return Code from email: ", returnCode)
		// fmt.Println()
		// code := getCode(email)
		// code, err := getJWT(email)
		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError) //err.Error() - type string
		// }
		// // cookie.Value = code + "|" + cookie.Value
		// fmt.Println("checked Code from email", code)
		// fmt.Println()
		// fmt.Println("********************************************************")
		// http.SetCookie(w, cookie)

		// set logged in flag
		message = "Not logged in!..."
		// isEqual = hmac.Equal([]byte(code), []byte(returnCode))

		//get the signed token from cookie
		ss := cookie.Value

		//check signature - this is weird!! you don't need an instance just a type of MyCustomClaims
		//this first uses the token(in the callback function) and then verifies it in the same step.
		verifiedToken, err := jwt.ParseWithClaims(ss, &MyCustomClaims{}, func(unverifiedToken *jwt.Token) (interface{}, error) {
			//according to jwt advisory you need to check if your signing method remained the same in callback.
			//the signing method are carried inside the unverified token.
			if unverifiedToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("someone tried changing the signing method")
			}
			return []byte(mySigningKey), nil
		})

		// Is the token valid?  It is populated when you Parse/Verify a token - only checks if the claims has not expired
		isEqual = err == nil && verifiedToken.Valid //important to check the error first nill pointer value see running video
		//need to assert VerifiedToken of *MyCustomeClaims type!! You know what you passed in when created.
		claims := verifiedToken.Claims.(*MyCustomClaims)

		//compare the new hmac to the cookie hmac

		if !isEqual { //code != returnCode
			cookie = &http.Cookie{} //reset cookie if not the same
		}
		//the token is verified:
		message = "Logged in!...as: " + claims.Data
		fmt.Printf("Claims: %v\n email: %s\n", claims, claims.Data)
		// cookie.Value = claims.Data
		// http.SetCookie(w, cookie)
		fmt.Println("*******************evaluating cookie****************************")
		fmt.Println()
	}

	html := `<!DOCTYPE html>
	<html>
		<head>
			<meta charset="utf-8">
			<meta http-equiv="X-UA-Compatible" content="IE=edge">
			<title>HMAC Example</title>
			<meta name="description" content="">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<link rel="stylesheet" href="">
		</head>
		<body>
			<p>Cookie Value: ` + cookie.Value + `</p>
			<p>` + message + `</p>
			<form method="POST" action="/submit">
				<input type="email" name="email">
				<input type="password" name="password">
				<input type="submit">
			</form>
		</body>
	</html>	
	`
	io.WriteString(w, html)
}

//handle the submit route
func submit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	email := req.FormValue("email")
	if email == "" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	// set cookie
	cookie, err := req.Cookie("session-id")
	// cookie not set
	if err != nil {
		//id, _ := uuid.NewV4()
		cookie = &http.Cookie{
			Name: "session-id",
		}
	}
	if req.FormValue("email") != "" {
		cookie.Value = req.FormValue("email")
	}
	// code := getCode(email)
	//get the code
	code, err := getJWT(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError) //err.Error() - type string
	}
	//sign the cookie
	cookie.Value = code
	http.SetCookie(w, cookie)
	fmt.Println("*******************signing cookie***********************")
	fmt.Println(" first Cookie : ", cookie.Value)
	fmt.Println()
	fmt.Println("**********************signing done****************************")
	fmt.Println()
	http.Redirect(w, req, "/", http.StatusSeeOther)

}
