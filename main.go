package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	msg := "This is totally awsome learning base64 encoding from the ground up!"

	password := "ilovedogs"
	bcryptPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Fatal(err)
	}
	bcryptPassX := bcryptPass[:16] //needs first 16 bytes for use as key

	//***********************************************************************
	//You can use your own encryptWriter with:
	wtr := &bytes.Buffer{}
	encWriter, err := encryptWriter(wtr, bcryptPassX)
	if err != nil {
		log.Fatalln(err)
	}
	//wite the message to your new encrypted writer
	_, err = io.WriteString(encWriter, msg)
	if err != nil {
		log.Fatalln(err)
	}
	// use the String method of the buffer to retrieve the encoded message
	encrypted := wtr.String()
	//with the new encrypted writer:
	fmt.Println("Encrypted msg: ", encrypted)
	rslt3, err := aesEncode(bcryptPassX, encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("AES decoded message: ", string(rslt3))
	//***********************************************************************

	//without the new encrypted writer:
	rslt, err := aesEncode(bcryptPassX, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("AES coded message without new encrypted writer: ", string(rslt))
	rslt2, err := aesEncode(bcryptPassX, string(rslt))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("AES decoded message without new encrypted writer: ", string(rslt2))

}

func encode(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
}

func decode(decodedMsg string) (string, error) {
	bs, err := base64.URLEncoding.DecodeString(decodedMsg)
	if err != nil {
		return "", fmt.Errorf("Cannot decode string: %w", err)
	}
	return string(bs), nil
}

// aesEncode uses aes to encode a message
func aesEncode(key []byte, input string) ([]byte, error) {
	// create new cipher block
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Could not create Cipher: %w", err)
	}
	// make the initialization vector (salt) aes block size as byte slice
	iv := make([]byte, aes.BlockSize)
	// // you could further randomize it, but then you need to return iv and split encode and decode
	// _, err = io.ReadFull(rand.Reader, iv)
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("Could not randomize iv: %w", err)
	// }
	s := cipher.NewCTR(b, iv)
	// create empty buffer
	buff := &bytes.Buffer{}
	// create encoding stream
	sw := cipher.StreamWriter{
		S: s,
		W: buff,
	}
	// write the input to the stream
	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("Cannot encode stream, %w", err)
	}
	return buff.Bytes(), nil

}

//encryptWriter changes a writer in an encrypted writer
func encryptWriter(wtr io.Writer, key []byte) (io.Writer, error) {
	// create new cipher block
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Could not create Cipher: %w", err)
	}
	// make the initialization vector (salt) aes block size as byte slice
	iv := make([]byte, aes.BlockSize)

	s := cipher.NewCTR(b, iv)
	return cipher.StreamWriter{
		S: s,
		W: wtr,
	}, nil
}
