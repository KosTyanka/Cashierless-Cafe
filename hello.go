package main

import (
	"fmt"
	"net/http"
	"encoding/json"
)

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type RequestData struct {
	Message string `json:"message"`
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fmt.Println("Got a succesful GET request")
		response := Response {
			Status: "Success",
			Message: "Success",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	} else {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		fmt.Println("GET got an Invalid Method error")
	}
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		fmt.Println("Post got an Invalid Method error")
		return
	}

	var data RequestData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil || data.Message == "" {
		response := Response{
			Status:  "fail",
			Message: "Invalid JSON message",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	fmt.Printf("Message received: %s\n", data.Message)





	response := Response{
		Status:  "success",
		Message: "Success",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/", getHandler)
	http.HandleFunc("/post", postHandler)

	srv := &http.Server {
		Addr: ":8080",
	}
	fmt.Println("Server is up")
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}