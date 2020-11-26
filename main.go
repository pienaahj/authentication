package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type person struct {
	First string
}

func main() {

	// handle routes
	http.HandleFunc("/encode", enJSON)

	http.HandleFunc("/decode", decJSON)
	// Create server
	http.ListenAndServe(":8080", nil)

}

func decJSON(w http.ResponseWriter, req *http.Request) {
	xp2 := []person{}
	err := json.NewDecoder(req.Body).Decode(&xp2)
	if err != nil {
		log.Println("Could not decode data: ", err)
	}
	log.Println("Decoded json: ", xp2)
}

func enJSON(w http.ResponseWriter, req *http.Request) {
	xp := []person{
		{
			First: "Jenny",
		},
		{
			First: "James",
		},
		{
			First: "Peter",
		},
	}
	err := json.NewEncoder(w).Encode(xp)
	if err != nil {
		log.Println("Could not encode data: ", err)
	}

	log.Println("Json encoding sent to client")
}
