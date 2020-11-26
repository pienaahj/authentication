package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person struct {
	First string
}

func main() {
	p1 := person{
		First: "Jenny",
	}

	p2 := person{
		First: "James",
	}

	xp := []person{p1, p2}

	bs, err := json.Marshal(xp)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("PRINT JSON ", string(bs))

	xp2 := []person{}

	err = json.Unmarshal(bs, &xp2)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("back into a Go data structure", xp2)

	// ########################################################################

	// Handle the routes
	http.HandleFunc("/encode", jsonEncoder)
	http.HandleFunc("/decode", jsonDecoder)

	// Create a server
	http.ListenAndServe(":8080", nil)

}

// Create a function that will handle the routes
func jsonEncoder(w http.ResponseWriter, r *http.Request) {
	p1 := person{
		First: "Jenny",
	}

	err := json.NewEncoder(w).Encode(p1)
	if err != nil {
		log.Println("Cannot encode bad data: ", err)
	}
}

func jsonDecoder(w http.ResponseWriter, r *http.Request) {
	var p1 person
	err := json.NewDecoder(r.Body).Decode(&p1)
	if err != nil {
		log.Println("Could not Decode bad Data: ", err)
	}

	log.Println("Person: ", p1)
}
