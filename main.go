package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//MyCustomClaims create type
type MyCustomClaims struct {
	Data string `json:"myclaimsfield"`
	jwt.StandardClaims
}

//create the key
const mySigningKey = "ourkey 1234"

func main() {
	http.HandleFunc("/", createTestCookie)
	http.HandleFunc("/submit", submit)
	http.ListenAndServe(":8080", nil)
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
