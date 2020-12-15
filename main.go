package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/gofrs/uuid"
	"github.com/pienaahj/authentication/conf"

	"golang.org/x/crypto/bcrypt"
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
	// handle the logout route
	http.HandleFunc("/logout", c.logout)

	http.Handle("/favicon.ico", http.NotFoundHandler())
	fmt.Println("server running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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

// **************************************************************************************************
