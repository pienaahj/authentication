package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

// jwt requires a signing method and claims type - MapClaims or StandardClaims

// UserClaims creates customs claims object
type UserClaims struct {
	jwt.StandardClaims //most simple Claims
	SessionID          int64
}

// Claims overrites the standard Claims method
func (u *UserClaims) Claims() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token expired")
	}
	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session")
	}
	return nil
}
func main() {
	// Generate the key(needs to be 64 bytes for sha512) insecure generate this by another means example only
	// for i := 1; i <= 64; i++ {
	// 	key = append(key, byte(i))
	// }
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

//HMAC - Hash Message Authentication Code - signing algorithm uses a key to sign a message.
// purpose to see if a message has changed
func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, keys[currentKID].key)
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

// createToken creates a token for use with jwt
func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES512, c)
	signedToken, err := t.SignedString(keys[currentKID].key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token : %w", err)
	}
	return signedToken, nil
}

// generateNewKey generates a key to use periodically, use a cron job to generate this every hour or so
func generateNewKey() error {
	newKey := make([]byte, 64)
	// fill byte slice with random values form reader
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey, while generating new key: %w", err)
	}
	//create a new uuid
	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey, while generating new key ID, %w", err)
	}
	// use the string function to get the string version of uuid
	keys[uuid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}
	currentKID = uuid.String()
	return nil
}

//create a key, remember to check through this periodically and remove old keys, say once a week
type key struct {
	key     []byte
	created time.Time
}

//create the current key id
var currentKID = ""

// create a key map, normally this needs tobe a dbase
var keys = map[string]key{}

// parseToken parses the token received
func parseToken(signedToken string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		// check that the algorithym presented by the token is actually the expected one.
		if t.Method.Alg() != jwt.SigningMethodES512.Alg() {
			return nil, fmt.Errorf("Invalid signing alorithym")
		}
		//you can use a spesific key
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}
		//lookup the key in keys
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}

		return k.key, nil //a key is returned at end of callback function
	})
	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while parsing token: %w", err)
	}
	if !t.Valid {
		return nil, fmt.Errorf(" Error in pasreToken, token not valid")
	}
	return t.Claims.(*UserClaims), nil
}
