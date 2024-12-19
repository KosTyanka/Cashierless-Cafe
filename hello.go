package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"

	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
)

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type RequestData struct {
	Message string `json:"message"`
}

type Drink struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Buyer string  `json:"buyer"`
	Cost  float64 `json:"cost"`
}

var db *sql.DB

func initDatabase() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	connStr := fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s sslmode=%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SSLMODE"),
	)

	var errOpen error
	db, errOpen = sql.Open("postgres", connStr)
	if errOpen != nil {
		log.Fatalf("Failed to connect to the database: %v", errOpen)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Database connection error: %v", err)
	}

	fmt.Println("Successfully connected to the database")
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fmt.Println("Got a successful GET request")
		response := Response{
			Status:  "Success",
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

func getDrinksHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, buyer, cost FROM drinks")
	if err != nil {
		http.Error(w, "Failed to fetch records", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var drinks []Drink
	for rows.Next() {
		var drink Drink
		if err := rows.Scan(&drink.ID, &drink.Name, &drink.Buyer, &drink.Cost); err != nil {
			http.Error(w, "Failed to scan record", http.StatusInternalServerError)
			return
		}
		drinks = append(drinks, drink)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drinks)
}

func getDrinkHandler(w http.ResponseWriter, r *http.Request, id string) {
	var drink Drink
	err := db.QueryRow("SELECT id, name, buyer, cost FROM drinks WHERE id = $1", id).Scan(&drink.ID, &drink.Name, &drink.Buyer, &drink.Cost)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Record not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to fetch record", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drink)
}

func createDrinkHandler(w http.ResponseWriter, r *http.Request) {
	var drink Drink
	err := json.NewDecoder(r.Body).Decode(&drink)
	if err != nil || drink.Name == "" || drink.Buyer == "" || drink.Cost <= 0 {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := "INSERT INTO drinks (name, buyer, cost) VALUES ($1, $2, $3) RETURNING id"
	err = db.QueryRow(query, drink.Name, drink.Buyer, drink.Cost).Scan(&drink.ID)
	if err != nil {
		http.Error(w, "Failed to create record", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drink)
}

func updateDrinkHandler(w http.ResponseWriter, r *http.Request) {
	var drink Drink
	err := json.NewDecoder(r.Body).Decode(&drink)
	if err != nil || drink.ID <= 0 || drink.Name == "" || drink.Buyer == "" || drink.Cost <= 0 {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := "UPDATE drinks SET name = $1, buyer = $2, cost = $3 WHERE id = $4"
	result, err := db.Exec(query, drink.Name, drink.Buyer, drink.Cost, drink.ID)
	if err != nil {
		http.Error(w, "Failed to update record", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drink)
}

func deleteDrinkHandler(w http.ResponseWriter, r *http.Request, id string) {
	query := "DELETE FROM drinks WHERE id = $1"
	result, err := db.Exec(query, id)
	if err != nil {
		http.Error(w, "Failed to delete record", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/index.html")
}


func main() {
	initDatabase()
	defer db.Close()

	http.HandleFunc("/", getHandler)
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/post", postHandler)
	http.HandleFunc("/drinks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getDrinksHandler(w, r)
		} else if r.Method == http.MethodPost {
			createDrinkHandler(w, r)
		} else {
			http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/drinks/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		idPattern := regexp.MustCompile(`^/drinks/(\d+)$`)
		matches := idPattern.FindStringSubmatch(path)
		if len(matches) == 2 {
			id := matches[1]
			if r.Method == http.MethodGet {
				getDrinkHandler(w, r, id)
			} else if r.Method == http.MethodPut {
				updateDrinkHandler(w, r)
			} else if r.Method == http.MethodDelete {
				deleteDrinkHandler(w, r, id)
			} else {
				http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
			}
		} else {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
		}
	})

	fmt.Println("Server is running on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
