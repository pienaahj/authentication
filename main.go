package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var key = []byte{}

func main() {
	// Generate the key(needs to be 64 bytes for sha512) insecure generate this by another means example only
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}
	// The use of UTF8 enables the password string to be any char even an emogi
	pass := "123456789"
	hashPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}
	err = comparePassword(pass, hashPass)
	if err != nil {
		log.Fatalln("Not logged in")
	}
	log.Println("logged in")
}

// Creating the password
func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

// Checking the password
func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}
	return nil
}

//HMAC - Hash Message Authentication Code - signing algorithm.
func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while signing message: %w", err)
	}
	// Sum appends the current hash and returns it.
	signature := h.Sum(nil)
	return signature, nil
}

// Check the signature and message against the signature
func checkSig(msg, sig []byte) (bool, error) {
	// Sign the new message
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSig while checking signature of message :%w", err)
	}
	same := hmac.Equal(newSig, sig)
	return same, nil
}
