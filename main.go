package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", createTestCookie)
	http.HandleFunc("/submit", submit)
	http.ListenAndServe(":8080", nil)
}
func getCode(data string) string {
	//create the hmac hash
	h := hmac.New(sha256.New, []byte("ourkey 1234"))
	//write the data passed in to the hash
	io.WriteString(h, data)
	//convert the hash to a string and return it
	return fmt.Sprintf("%x", h.Sum(nil))
}

//handle the root route - create the cookie - test if cookie is the same as created - then on logged in
func createTestCookie(w http.ResponseWriter, req *http.Request) {
	//get cookie back
	cookie, err := req.Cookie("session-id")
	if err != nil {
		cookie = &http.Cookie{}
	}
	//setting message
	message := "Not logged in!..."
	isEqual := true
	//testing cookie
	if len(cookie.Value) != 0 {
		fmt.Println("*******************testing cookie****************************")
		fmt.Println("Cookie: ", cookie.Value)
		fmt.Println()

		//get the email from cookie
		email := strings.SplitAfter(cookie.Value, "|")[1]
		fmt.Println("Cookie email: ", strings.Split(cookie.Value, "|")[1])
		fmt.Println()
		//get the hmac from cookie
		returnCode := strings.Split(cookie.Value, "|")[0]
		fmt.Println("Return Code from email: ", returnCode)
		fmt.Println()
		code := getCode(email)
		// cookie.Value = code + "|" + cookie.Value
		fmt.Println("checked Code from email", code)
		fmt.Println()
		fmt.Println("********************************************************")
		http.SetCookie(w, cookie)
		// set logged in flag
		message = "Not logged in!..."
		isEqual = hmac.Equal([]byte(code), []byte(returnCode))
		if isEqual {
			message = "Logged in!..."
		}
		//compare the new hmac to the cookie hmac
		if !isEqual { //code != returnCode
			cookie = &http.Cookie{} //reset cookie if not the same
		}
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
	code := getCode(email)
	//sign the cookie
	cookie.Value = code + "|" + email
	http.SetCookie(w, cookie)
	fmt.Println("********************************************************")
	fmt.Println(" first Cookie : ", cookie.Value)
	fmt.Println()
	fmt.Println("********************************************************")
	http.Redirect(w, req, "/", http.StatusSeeOther)

}
