package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	msg := "This is totally awsome learning base64 encoding from the ground up!"
	encodedMsg := encode(msg)
	fmt.Println("Encoded message: ", encodedMsg)
	decodedMsg, err := decode(encodedMsg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Decoded message: ", decodedMsg)

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
