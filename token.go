package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//MyCustomClaims create type
type MyCustomClaims struct {
	Data string `json:"myclaimsfield"`
	jwt.StandardClaims
}

// const mySigningKey = "ourkey 1234"

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
		return "", fmt.Errorf("could not sign token in SignedString: %w", err)
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
