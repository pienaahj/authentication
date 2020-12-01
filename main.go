package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	//open the file
	filename := "sample_file.txt"
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	//create the hash
	h := sha256.New()
	//write the file content to the hash
	_, err = io.Copy(h, f)
	if err != nil {
		log.Fatalln("Could not copy hash ", err)
	}
	fmt.Println()
	//Digest type(*sha256.digest):
	// A message digest is a fixed size numeric representation of the contents of a message,
	//computed by a hash function. A message digest can be encrypted, forming a digital signature.
	//Messages are inherently variable in size. ...
	// It must be computationally infeasible to find two messages that hash to the same digest.
	fmt.Printf("Here is the type of the hash before sum: %T\n", h)
	fmt.Println()
	fmt.Printf("SHA256 hash created: %v\n ", h)
	fmt.Println()
	bs := h.Sum(nil)
	//print the hash
	fmt.Printf("Here is the type of the hash bafter sum: %T\n", bs)
	fmt.Println()
	fmt.Printf("SHA256 hash created: %x\n ", bs)
	fmt.Println()
}
