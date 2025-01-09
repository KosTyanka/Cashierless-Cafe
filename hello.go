package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
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

type EmailRequest struct {
	EmailTo      string `json:"emailTo"`
	EmailSubject string `json:"emailSubject"`
	EmailBody    string `json:"emailBody"`
}

type SupportRequest struct {
	Subject string `json:"subject"`
	Message string `json:"message"`
}

var db *sql.DB
var logg = logrus.New()
var limiter = rate.NewLimiter(2, 5)

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			logg.WithField("client_ip", r.RemoteAddr).Warn("Rate limit exceeded")
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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
	dbx, errOpen := sql.Open("postgres", connStr)
	if errOpen != nil {
		logg.WithError(errOpen).Fatal("Failed to connect to the database")
	}
	errPing := dbx.Ping()
	if errPing != nil {
		logg.WithError(errPing).Fatal("Database connection error")
	}
	logg.Info("Successfully connected to the database")
	db = dbx
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logg.Warn("Invalid method for sendEmailHandler")
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	var req EmailRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || strings.TrimSpace(req.EmailTo) == "" {
		logg.WithError(err).Warn("Invalid email request data")
		http.Error(w, "Invalid email request data", http.StatusBadRequest)
		return
	}
	from := os.Getenv("EMAIL_USER")
	pass := os.Getenv("EMAIL_PASS")
	host := os.Getenv("EMAIL_HOST")
	port := os.Getenv("EMAIL_PORT")
	auth := smtp.PlainAuth("", from, pass, host)
	to := []string{req.EmailTo}
	msg := []byte("To: " + req.EmailTo + "\r\n" +
		"Subject: " + req.EmailSubject + "\r\n\r\n" +
		req.EmailBody + "\r\n")
	errSend := smtp.SendMail(host+":"+port, auth, from, to, msg)
	if errSend != nil {
		logg.WithError(errSend).Error("Failed to send email")
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "Email sent"})
	logg.WithFields(logrus.Fields{"to": req.EmailTo, "subject": req.EmailSubject}).Info("Email sent successfully")
}

func sendSupportEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logg.Warn("Invalid method for sendSupportEmailHandler")
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	var req SupportRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || strings.TrimSpace(req.Subject) == "" {
		logg.WithError(err).Warn("Invalid support request data")
		http.Error(w, "Invalid support request data", http.StatusBadRequest)
		return
	}
	from := os.Getenv("EMAIL_USER")
	pass := os.Getenv("EMAIL_PASS")
	host := os.Getenv("EMAIL_HOST")
	port := os.Getenv("EMAIL_PORT")
	supportEmail := os.Getenv("SUPPORT_EMAIL")
	auth := smtp.PlainAuth("", from, pass, host)
	to := []string{supportEmail}
	msg := []byte("To: " + supportEmail + "\r\n" +
		"Subject: " + req.Subject + "\r\n\r\n" +
		req.Message + "\r\n")
	errSend := smtp.SendMail(host+":"+port, auth, from, to, msg)
	if errSend != nil {
		logg.WithError(errSend).Error("Failed to send support email")
		http.Error(w, "Failed to send support email", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Status: "success", Message: "Support email sent"})
	logg.WithFields(logrus.Fields{"subject": req.Subject}).Info("Support email sent successfully")
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		resp := Response{Status: "Success", Message: "Success"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		logg.WithField("endpoint", "/").Info("GET request successful")
	} else {
		logg.WithField("endpoint", "/").Warn("Invalid Method for GET")
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
	}
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logg.Warn("Invalid Method for POST")
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	var data RequestData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil || data.Message == "" {
		logg.WithError(err).Warn("Invalid JSON message in POST")
		resp := Response{Status: "fail", Message: "Invalid JSON message"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}
	resp := Response{Status: "success", Message: "Success"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	logg.WithField("message", data.Message).Info("POST request successful")
}

func getDrinksHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sortField := r.URL.Query().Get("sort")
	pageStr := r.URL.Query().Get("page")
	page := 1
	limit := 5
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	offset := (page - 1) * limit
	query := "SELECT id, name, buyer, cost FROM drinks"
	conds := []string{}
	if filter != "" {
		conds = append(conds, fmt.Sprintf("(name ILIKE '%%%s%%' OR buyer ILIKE '%%%s%%')", filter, filter))
	}
	if len(conds) > 0 {
		query += " WHERE " + conds[0]
	}
	validSorts := map[string]bool{"name": true, "cost": true}
	if sortField != "" && validSorts[sortField] {
		query += " ORDER BY " + sortField
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	rows, err := db.Query(query)
	if err != nil {
		logg.WithError(err).Error("Failed to fetch drinks")
		http.Error(w, "Failed to fetch records", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var drinks []Drink
	for rows.Next() {
		var drink Drink
		if err := rows.Scan(&drink.ID, &drink.Name, &drink.Buyer, &drink.Cost); err != nil {
			logg.WithError(err).Error("Failed to scan record")
			http.Error(w, "Failed to scan record", http.StatusInternalServerError)
			return
		}
		drinks = append(drinks, drink)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drinks)
	logg.WithFields(logrus.Fields{"endpoint": "/drinks", "count": len(drinks)}).Info("GET drinks request")
}

func getDrinkHandler(w http.ResponseWriter, r *http.Request, id string) {
	var drink Drink
	err := db.QueryRow("SELECT id, name, buyer, cost FROM drinks WHERE id = $1", id).Scan(&drink.ID, &drink.Name, &drink.Buyer, &drink.Cost)
	if err != nil {
		if err == sql.ErrNoRows {
			logg.WithField("id", id).Warn("Drink not found")
			http.Error(w, "Record not found", http.StatusNotFound)
		} else {
			logg.WithError(err).Error("Failed to fetch record")
			http.Error(w, "Failed to fetch record", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drink)
	logg.WithField("id", id).Info("Fetched single drink")
}

func createDrinkHandler(w http.ResponseWriter, r *http.Request) {
	var drink Drink
	err := json.NewDecoder(r.Body).Decode(&drink)
	if err != nil || drink.Name == "" || drink.Buyer == "" || drink.Cost <= 0 {
		logg.WithError(err).Warn("Invalid input for creating a drink")
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	query := "INSERT INTO drinks (name, buyer, cost) VALUES ($1, $2, $3) RETURNING id"
	err = db.QueryRow(query, drink.Name, drink.Buyer, drink.Cost).Scan(&drink.ID)
	if err != nil {
		logg.WithError(err).Error("Failed to create record in DB")
		http.Error(w, "Failed to create record", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drink)
	logg.WithField("id", drink.ID).Info("Created a new drink")
}

func updateDrinkHandler(w http.ResponseWriter, r *http.Request) {
	var drink Drink
	err := json.NewDecoder(r.Body).Decode(&drink)
	if err != nil || drink.ID <= 0 || drink.Name == "" || drink.Buyer == "" || drink.Cost <= 0 {
		logg.WithError(err).Warn("Invalid input for updating a drink")
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	query := "UPDATE drinks SET name = $1, buyer = $2, cost = $3 WHERE id = $4"
	result, err := db.Exec(query, drink.Name, drink.Buyer, drink.Cost, drink.ID)
	if err != nil {
		logg.WithError(err).Error("Failed to update record in DB")
		http.Error(w, "Failed to update record", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logg.WithField("id", drink.ID).Warn("Drink record not found for update")
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(drink)
	logg.WithField("id", drink.ID).Info("Updated drink")
}

func deleteDrinkHandler(w http.ResponseWriter, r *http.Request, id string) {
	query := "DELETE FROM drinks WHERE id = $1"
	result, err := db.Exec(query, id)
	if err != nil {
		logg.WithError(err).Error("Failed to delete record in DB")
		http.Error(w, "Failed to delete record", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		logg.WithField("id", id).Warn("Drink record not found for delete")
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	logg.WithField("id", id).Info("Deleted drink")
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/index.html")
	logg.WithField("endpoint", "/index").Info("Served index.html")
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/admin.html")
	logg.WithField("endpoint", "/admin").Info("Served admin.html")
}

func userProfileHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/userProfile.html")
	logg.WithField("endpoint", "/userProfile").Info("Served userProfile.html")
}

func main() {
	logg.SetFormatter(&logrus.JSONFormatter{})
	logg.SetLevel(logrus.InfoLevel)
	initDatabase()
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", getHandler)
	mux.HandleFunc("/index", indexHandler)
	mux.HandleFunc("/admin", adminHandler)
	mux.HandleFunc("/userProfile", userProfileHandler)
	mux.HandleFunc("/admin/sendEmail", sendEmailHandler)
	mux.HandleFunc("/user/sendSupportEmail", sendSupportEmailHandler)
	mux.HandleFunc("/post", postHandler)
	mux.HandleFunc("/drinks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getDrinksHandler(w, r)
		} else if r.Method == http.MethodPost {
			createDrinkHandler(w, r)
		} else {
			logg.Warn("Invalid Method for /drinks")
			http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/drinks/", func(w http.ResponseWriter, r *http.Request) {
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
				logg.Warn("Invalid Method for /drinks/:id")
				http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
			}
		} else {
			logg.Warn("Invalid URL for /drinks/")
			http.Error(w, "Invalid URL", http.StatusBadRequest)
		}
	})
	srv := &http.Server{Addr: ":8080", Handler: rateLimitMiddleware(mux)}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logg.WithError(err).Fatal("ListenAndServe error")
		}
	}()
	logg.Info("Server is running on localhost:8080")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	logg.Warn("Received shutdown signal")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logg.WithError(err).Fatal("Server forced to shutdown")
	}
	logg.Info("Server exited gracefully")
}
