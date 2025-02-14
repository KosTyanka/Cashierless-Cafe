package main

import (
    "bytes"
    "context"
    "database/sql"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "html/template"
    "log"
    "mime/multipart"
    "net/http"
    "net/smtp"
    "net/textproto"
    "os"
    "os/signal"
    "regexp"
    "strconv"
    "strings"
    "syscall"
    "time"

    _ "github.com/lib/pq"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/joho/godotenv"
    "github.com/sirupsen/logrus"
    "golang.org/x/crypto/bcrypt"
    "golang.org/x/time/rate"
    "github.com/gorilla/websocket"
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
    EmailTo      string   `json:"emailTo"`
    EmailSubject string   `json:"emailSubject"`
    EmailBody    string   `json:"emailBody"`
    Attachments  []string `json:"attachments"`
}

type SupportRequest struct {
    Subject     string   `json:"subject"`
    Message     string   `json:"message"`
    Attachments []string `json:"attachments"`
    FullName    string   `json:"full_name,omitempty"`
    Email       string   `json:"email,omitempty"`
}


type SignUpRequest struct {
    FullName string `json:"full_name"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type VerificationToken struct {
    Token string
    Email string
}

type MicroserviceResponse struct {
    PaymentURL     string `json:"paymentURL"`
    PaymentSuccess bool   `json:"paymentSuccess"`
    Status         string `json:"status"`
    Receipt        string `json:"receipt"`
}


type UserProfileData struct {
    FullName string
}

var jwtKey = []byte("your_secret_key")

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

var db *sql.DB
var logg = logrus.New()
var limiter = rate.NewLimiter(2, 5)
var verificationTokens = make(map[string]string)

type contextKey string

var userIDKey = contextKey("userID")
var roleIDKey = contextKey("roleID")

var chatUpgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { 
        // Adjust this as needed (for demo purposes, we allow all origins)
        return true 
    },
}

type ChatMessage struct {
    Username  string `json:"username"`
    Content   string `json:"content"`
    Timestamp string `json:"timestamp"`
}

type ChatSession struct {
    ChatID   string
    UserID   int
    Username string
    Conn     *websocket.Conn
}

type AdminPanelData struct {
    FullName    string
    ActiveChats []*ChatSession
}


type ChatSummary struct {
    ChatID   string
    Username string
}

var activeUserChats = make(map[int]*ChatSession)
var activeAdminConn *websocket.Conn

// sendJSONError writes error responses as JSON alerts.
func sendJSONError(w http.ResponseWriter, code int, message string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(map[string]string{"alert": message})
}

func rateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            logg.WithField("client_ip", r.RemoteAddr).Warn("Rate limit exceeded")
            sendJSONError(w, http.StatusTooManyRequests, "429 Too Many Requests")
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

    var errOpen error
    db, errOpen = sql.Open("postgres", connStr)
    if errOpen != nil {
        log.Fatalf("Failed to connect to the database: %v", errOpen)
    }

    errPing := db.Ping()
    if errPing != nil {
        log.Fatalf("Database connection error: %v", errPing)
    }

    log.Println("Connected to the existing database successfully.")
    createTables()
}

func createTables() {
    queries := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role_id INT DEFAULT 3,
            is_verified BOOLEAN DEFAULT FALSE
        );`,
        `CREATE TABLE IF NOT EXISTS drinks (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            buyer TEXT NOT NULL,
            cost DECIMAL NOT NULL
        );`,
        `CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            action TEXT NOT NULL,
            user_id INT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );`,
    }

    for _, query := range queries {
        _, err := db.Exec(query)
        if err != nil {
            log.Fatalf("Error creating table: %v", err)
        }
    }

    log.Println("Tables checked/created successfully.")
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendJSONError(w, http.StatusMethodNotAllowed, "Invalid Method")
        return
    }
    var req EmailRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.EmailTo) == "" {
        sendJSONError(w, http.StatusBadRequest, "Invalid email request data")
        return
    }
    // Try to retrieve sender info from token, if available.
    var senderInfo string
    if userID, _, err := getAuthenticatedUser(r); err == nil {
        var fullName, senderEmail string
        if err := db.QueryRow("SELECT full_name, email FROM users WHERE id=$1", userID).Scan(&fullName, &senderEmail); err == nil {
            senderInfo = fmt.Sprintf("Sent by: %s (%s)\n\n", fullName, senderEmail)
        }
    }
    // Prepend sender info (if any) to the email body.
    req.EmailBody = senderInfo + req.EmailBody

    from := os.Getenv("EMAIL_USER")
    pass := os.Getenv("EMAIL_PASS")
    host := os.Getenv("EMAIL_HOST")
    port := os.Getenv("EMAIL_PORT")
    smtpAuth := smtp.PlainAuth("", from, pass, host)
    to := []string{req.EmailTo}

    var emailBuffer bytes.Buffer
    writer := multipart.NewWriter(&emailBuffer)

    headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%s\r\n\r\n",
        from, req.EmailTo, req.EmailSubject, writer.Boundary())
    if _, err := emailBuffer.Write([]byte(headers)); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to write email headers")
        return
    }

    // Create one plain-text part containing the sender info and message.
    bodyHeader := make(textproto.MIMEHeader)
    bodyHeader.Set("Content-Type", "text/plain; charset=UTF-8")
    bodyPart, err := writer.CreatePart(bodyHeader)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to create message part")
        return
    }
    if _, err := bodyPart.Write([]byte(req.EmailBody)); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to write email message")
        return
    }

    // Process attachments (if any) as before.
    for i, attachBase64 := range req.Attachments {
        decoded, errDecode := base64.StdEncoding.DecodeString(attachBase64)
        if errDecode != nil {
            sendJSONError(w, http.StatusBadRequest, "Invalid attachment encoding")
            return
        }
        attachHeader := make(textproto.MIMEHeader)
        filename := fmt.Sprintf("attachment%d.jpg", i+1)
        attachHeader.Set("Content-Type", "image/jpeg")
        attachHeader.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
        attachHeader.Set("Content-Transfer-Encoding", "base64")
        part, errPart := writer.CreatePart(attachHeader)
        if errPart != nil {
            sendJSONError(w, http.StatusInternalServerError, "Failed to process attachment")
            return
        }
        encodedAttachment := base64.StdEncoding.EncodeToString(decoded)
        formattedAttachment := chunkBase64(encodedAttachment)
        if _, err := part.Write([]byte(formattedAttachment)); err != nil {
            sendJSONError(w, http.StatusInternalServerError, "Failed to write attachment data")
            return
        }
    }

    if err := writer.Close(); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to finalize email")
        return
    }

    if errSend := smtp.SendMail(host+":"+port, smtpAuth, from, to, emailBuffer.Bytes()); errSend != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to send email")
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(Response{Status: "success", Message: "Email sent"})
}

func getTokenFromRequest(r *http.Request) (string, error) {
    authHeader := r.Header.Get("Authorization")
    if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
        return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")), nil
    }
    if cookie, err := r.Cookie("jwt_token"); err == nil {
        return strings.TrimSpace(cookie.Value), nil
    }
    return "", errors.New("No token found")
}

func chunkBase64(input string) string {
    var result strings.Builder
    for i := 0; i < len(input); i += 76 {
        end := i + 76
        if end > len(input) {
            end = len(input)
        }
        result.WriteString(input[i:end] + "\r\n")
    }
    return result.String()
}

func sendSupportEmailHandler(w http.ResponseWriter, r *http.Request) {
    var req SupportRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Subject) == "" {
        sendJSONError(w, http.StatusBadRequest, "Invalid support request data")
        return
    }

    // Try to get sender info from token.
    fullName := req.FullName
    senderEmail := req.Email
    if tokenStr, err := getTokenFromRequest(r); err == nil && tokenStr != "" {
        if userID, _, err := getAuthenticatedUser(r); err == nil {
            var dbName, dbEmail string
            if err := db.QueryRow("SELECT full_name, email FROM users WHERE id=$1", userID).Scan(&dbName, &dbEmail); err == nil {
                fullName = dbName
                senderEmail = dbEmail
            }
        }
    }

    // Ensure we have both sender name and email.
    if strings.TrimSpace(fullName) == "" || strings.TrimSpace(senderEmail) == "" {
        sendJSONError(w, http.StatusBadRequest, "Full name and email are required")
        return
    }

    // Build the email body: first sender info, then a blank line, then the actual message.
    combinedMessage := fmt.Sprintf("User: %s\nEmail: %s\n\n%s", fullName, senderEmail, req.Message)

    from := os.Getenv("EMAIL_USER")
    pass := os.Getenv("EMAIL_PASS")
    host := os.Getenv("EMAIL_HOST")
    port := os.Getenv("EMAIL_PORT")
    supportEmailAddr := os.Getenv("SUPPORT_EMAIL")
    smtpAuth := smtp.PlainAuth("", from, pass, host)
    to := []string{supportEmailAddr}

    var buf bytes.Buffer
    mw := multipart.NewWriter(&buf)
    headers := fmt.Sprintf(
        "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%s\r\n\r\n",
        from, supportEmailAddr, req.Subject, mw.Boundary(),
    )
    if _, err := buf.Write([]byte(headers)); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to write email headers")
        return
    }

    // Create one plain-text part with the combined message.
    bodyHeader := make(textproto.MIMEHeader)
    bodyHeader.Set("Content-Type", "text/plain; charset=UTF-8")
    bodyPart, err := mw.CreatePart(bodyHeader)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to create email body part")
        return
    }
    if _, err = bodyPart.Write([]byte(combinedMessage)); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to write email body")
        return
    }

    // Process attachments (if any).
    for i, attachBase64 := range req.Attachments {
        decoded, errDecode := base64.StdEncoding.DecodeString(attachBase64)
        if errDecode != nil {
            sendJSONError(w, http.StatusBadRequest, "Invalid attachment encoding")
            return
        }
        attachHeader := make(textproto.MIMEHeader)
        filename := fmt.Sprintf("support_image%d.jpg", i+1)
        attachHeader.Set("Content-Type", "image/jpeg")
        attachHeader.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
        attachHeader.Set("Content-Transfer-Encoding", "base64")
        part, errPart := mw.CreatePart(attachHeader)
        if errPart != nil {
            sendJSONError(w, http.StatusInternalServerError, "Failed to process attachment")
            return
        }
        encodedAttachment := base64.StdEncoding.EncodeToString(decoded)
        formattedAttachment := chunkBase64(encodedAttachment)
        if _, err = part.Write([]byte(formattedAttachment)); err != nil {
            sendJSONError(w, http.StatusInternalServerError, "Failed to write attachment data")
            return
        }
    }

    if err = mw.Close(); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to finalize email")
        return
    }

    if errSend := smtp.SendMail(host+":"+port, smtpAuth, from, to, buf.Bytes()); errSend != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to send support email")
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(Response{Status: "success", Message: "Support email sent successfully"})
}


func getHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        resp := Response{Status: "Success", Message: "Success"}
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(resp)
        logg.WithField("endpoint", "/").Info("GET request successful")
    } else {
        logg.WithField("endpoint", "/").Warn("Invalid Method for GET")
        sendJSONError(w, http.StatusMethodNotAllowed, "Invalid Method")
    }
}

func postHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        logg.Warn("Invalid Method for POST")
        sendJSONError(w, http.StatusMethodNotAllowed, "Invalid Method")
        return
    }
    var data RequestData
    err := json.NewDecoder(r.Body).Decode(&data)
    if err != nil || data.Message == "" {
        logg.WithError(err).Warn("Invalid JSON message in POST")
        sendJSONError(w, http.StatusBadRequest, "Invalid JSON message")
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
        sendJSONError(w, http.StatusInternalServerError, "Failed to fetch records")
        return
    }
    defer rows.Close()
    var drinks []Drink
    for rows.Next() {
        var drink Drink
        if err := rows.Scan(&drink.ID, &drink.Name, &drink.Buyer, &drink.Cost); err != nil {
            logg.WithError(err).Error("Failed to scan record")
            sendJSONError(w, http.StatusInternalServerError, "Failed to scan record")
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
            sendJSONError(w, http.StatusNotFound, "Record not found")
        } else {
            logg.WithError(err).Error("Failed to fetch record")
            sendJSONError(w, http.StatusInternalServerError, "Failed to fetch record")
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
        sendJSONError(w, http.StatusBadRequest, "Invalid input")
        return
    }
    query := "INSERT INTO drinks (name, buyer, cost) VALUES ($1, $2, $3) RETURNING id"
    err = db.QueryRow(query, drink.Name, drink.Buyer, drink.Cost).Scan(&drink.ID)
    if err != nil {
        logg.WithError(err).Error("Failed to create record in DB")
        sendJSONError(w, http.StatusInternalServerError, "Failed to create record")
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
        sendJSONError(w, http.StatusBadRequest, "Invalid input")
        return
    }
    query := "UPDATE drinks SET name = $1, buyer = $2, cost = $3 WHERE id = $4"
    result, err := db.Exec(query, drink.Name, drink.Buyer, drink.Cost, drink.ID)
    if err != nil {
        logg.WithError(err).Error("Failed to update record in DB")
        sendJSONError(w, http.StatusInternalServerError, "Failed to update record")
        return
    }
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        logg.WithField("id", drink.ID).Warn("Drink record not found for update")
        sendJSONError(w, http.StatusNotFound, "Record not found")
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
        sendJSONError(w, http.StatusInternalServerError, "Failed to delete record")
        return
    }
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        logg.WithField("id", id).Warn("Drink record not found for delete")
        sendJSONError(w, http.StatusNotFound, "Record not found")
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
    userID, _, err := getAuthenticatedUser(r)
    if err != nil {
        http.Redirect(w, r, "/login-page", http.StatusSeeOther)
        return
    }
    var email, fullName string
    err = db.QueryRow("SELECT email, full_name FROM users WHERE id=$1", userID).Scan(&email, &fullName)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to fetch user info")
        return
    }
    if email != os.Getenv("ADMIN_EMAIL") {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `<script>
            alert("Forbidden: Only the designated admin can access this page");
            window.location.href="/login-page";
            </script>`)
        return
    }
    data := AdminPanelData{
        FullName:    "Administrative Panel - Welcome, " + fullName,
        ActiveChats: getActiveChats(),
    }
    tmpl, err := template.ParseFiles("templates/admin.html")
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Template error")
        return
    }
    if err = tmpl.Execute(w, data); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to render template")
        return
    }
}


func userProfileHandler(w http.ResponseWriter, r *http.Request) {
    // The user must be authenticated via authMiddleware.
    userID := r.Context().Value(userIDKey).(int)
    var fullName, email string
    err := db.QueryRow("SELECT full_name, email FROM users WHERE id=$1", userID).Scan(&fullName, &email)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Unable to fetch user info")
        return
    }
    data := struct {
        FullName string
        Email    string
    }{
        FullName: "Welcome, " + fullName,
        Email:    email,
    }
    tmpl, err := template.ParseFiles("templates/userProfile.html")
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Template error")
        return
    }
    if err = tmpl.Execute(w, data); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to render template")
    }
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
        return
    }

    var req SignUpRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendJSONError(w, http.StatusBadRequest, "Invalid JSON request body")
        return
    }

    // Trim input values to avoid unnecessary spaces
    req.FullName = strings.TrimSpace(req.FullName)
    req.Email = strings.TrimSpace(req.Email)
    req.Password = strings.TrimSpace(req.Password)

    // Validate input fields
    if req.FullName == "" || req.Email == "" || req.Password == "" {
        sendJSONError(w, http.StatusBadRequest, "Full name, email, and password are required fields")
        return
    }

    if err := ValidatePassword(req.Password); err != nil {
        sendJSONError(w, http.StatusBadRequest, err.Error())
        return
    }

    // Check if email already exists
    var exists bool
    err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email=$1)", req.Email).Scan(&exists)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Database error while checking email")
        return
    }
    if exists {
        sendJSONError(w, http.StatusConflict, "Email is already registered")
        return
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Error hashing password")
        return
    }

    // Insert new user into the database
    _, err = db.Exec("INSERT INTO users (full_name, email, password, role_id) VALUES ($1, $2, $3, $4)",
        req.FullName, req.Email, string(hashedPassword), 3)

    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Error inserting user into database")
        return
    }

    // Generate verification token and send email
    token := uuid.NewString()
    verificationTokens[token] = req.Email
    sendVerificationEmail(req.Email, token)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "User registered successfully. Please check your email to verify your account.",
    })
}


func ValidatePassword(password string) error {
    if len(password) < 6 {
        return errors.New("Password too short. Minimum length is 6 characters.")
    }
    return nil
}

func sendVerificationEmail(email, token string) {
    from := os.Getenv("EMAIL_USER")
    pass := os.Getenv("EMAIL_PASS")
    host := os.Getenv("EMAIL_HOST")
    port := os.Getenv("EMAIL_PORT")
    subject := "Verify Your Account"
    body := fmt.Sprintf("Please verify your account by clicking: http://localhost:8080/verify?token=%s", token)
    msg := []byte("To: " + email + "\r\n" +
        "Subject: " + subject + "\r\n\r\n" +
        body + "\r\n")
    auth := smtp.PlainAuth("", from, pass, host)
    smtp.SendMail(host+":"+port, auth, from, []string{email}, msg)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    email, ok := verificationTokens[token]
    if !ok {
        sendJSONError(w, http.StatusBadRequest, "Invalid token")
        return
    }
    delete(verificationTokens, token)
    _, err := db.Exec("UPDATE users SET is_verified = TRUE WHERE email = $1", email)
    if err != nil {
        logg.WithError(err).Error("DB error during verification")
        sendJSONError(w, http.StatusInternalServerError, "Failed to verify user")
        return
    }
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        http.ServeFile(w, r, "templates/login.html")
        logg.WithField("endpoint", "/login").Info("Served login.html")
    case http.MethodPost:
        var req LoginRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            sendJSONError(w, http.StatusBadRequest, "Invalid input")
            return
        }
        var storedHash string
        var userID int
        var isVerified bool
        var roleID int
        err := db.QueryRow("SELECT id, password, is_verified, role_id FROM users WHERE email=$1", req.Email).
            Scan(&userID, &storedHash, &isVerified, &roleID)
        if err != nil {
            sendJSONError(w, http.StatusUnauthorized, "Invalid credentials")
            return
        }
        if !isVerified {
            sendJSONError(w, http.StatusForbidden, "Email not verified")
            return
        }
        if err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
            sendJSONError(w, http.StatusUnauthorized, "Invalid credentials")
            return
        }
        // Now fetch full name and email from the database.
        var fullName, email string
        if err := db.QueryRow("SELECT full_name, email FROM users WHERE id=$1", userID).Scan(&fullName, &email); err != nil {
            sendJSONError(w, http.StatusInternalServerError, "Failed to fetch user info")
            return
        }
        tokenString, err := generateJWTToken(userID, roleID, fullName, email)
        if err != nil {
            sendJSONError(w, http.StatusInternalServerError, "Token generation failed")
            return
        }
        // Set the token in a cookie.
        cookie := &http.Cookie{
            Name:  "jwt_token",
            Value: tokenString,
            Path:  "/",
            // Optionally add Secure and HttpOnly flags.
        }
        http.SetCookie(w, cookie)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
    default:
        sendJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
    }
}


func generateJWTToken(userID, roleID int, fullName, email string) (string, error) {
    now := time.Now()
    claims := jwt.MapClaims{
        "user_id":   userID,
        "role_id":   roleID,
        "full_name": fullName,
        "email":     email,
        "exp":       now.Add(24 * time.Hour).Unix(),
        "iat":       now.Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtKey)
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := ""
        authHeader := r.Header.Get("Authorization")
        if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
            tokenString = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
        } else {
            if cookie, err := r.Cookie("jwt_token"); err == nil {
                tokenString = strings.TrimSpace(cookie.Value)
            }
        }
        if tokenString == "" {
            // For protected routes, redirect to login instead of returning JSON error.
            if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/user") {
                http.Redirect(w, r, "/login-page", http.StatusSeeOther)
                return
            }
            sendJSONError(w, http.StatusUnauthorized, "Missing or invalid token")
            return
        }
        claims := jwt.MapClaims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })
        if err != nil || !token.Valid {
            if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/user") {
                http.Redirect(w, r, "/login-page", http.StatusSeeOther)
                return
            }
            sendJSONError(w, http.StatusUnauthorized, "Invalid token")
            return
        }
        userID, ok1 := claims["user_id"].(float64)
        roleID, ok2 := claims["role_id"].(float64)
        if !ok1 || !ok2 {
            if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/user") {
                http.Redirect(w, r, "/login-page", http.StatusSeeOther)
                return
            }
            sendJSONError(w, http.StatusUnauthorized, "Invalid token claims")
            return
        }
        ctx := context.WithValue(r.Context(), userIDKey, int(userID))
        ctx = context.WithValue(ctx, roleIDKey, int(roleID))
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}




func adminOnlyHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve authenticated user's ID from context.
    userID, _, err := getAuthenticatedUser(r)
    if err != nil {
        http.Redirect(w, r, "/login-page", http.StatusSeeOther)
        return
    }
    // Query the user's email from the database.
    var email string
    err = db.QueryRow("SELECT email FROM users WHERE id=$1", userID).Scan(&email)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to fetch user email")
        return
    }
    // Compare with the designated admin email from environment.
    if email != os.Getenv("ADMIN_EMAIL") {
        sendJSONError(w, http.StatusForbidden, "Forbidden: Only designated admin can access this page")
        return
    }
    w.Write([]byte("Welcome, Admin!"))
}

func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
    userID, _, err := getAuthenticatedUser(r)
    if err != nil {
        http.Redirect(w, r, "/login-page", http.StatusSeeOther)
        return
    }
    var email, fullName string
    err = db.QueryRow("SELECT email, full_name FROM users WHERE id=$1", userID).Scan(&email, &fullName)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Unable to fetch admin info")
        return
    }
    if email != os.Getenv("ADMIN_EMAIL") {
        sendJSONError(w, http.StatusForbidden, "Forbidden: Only designated admin can access this page")
        return
    }
    data := AdminPanelData{
        FullName:    "Administrative Panel - Welcome, " + fullName,
        ActiveChats: getActiveChats(),
    }
    tmpl, err := template.ParseFiles("templates/admin.html")
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Template error")
        return
    }
    if err = tmpl.Execute(w, data); err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to render template")
        return
    }
}


func loginPageHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        http.ServeFile(w, r, "templates/login.html")
        logg.WithField("endpoint", "/login-page").Info("Served login.html")
    } else {
        sendJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
    }
}

func promoteUserHandler(w http.ResponseWriter, r *http.Request) {
    roleID := r.Context().Value(roleIDKey).(int)
    if roleID != 1 {
        sendJSONError(w, http.StatusForbidden, "Forbidden: Admins only")
        return
    }
    if r.Method != http.MethodPost {
        sendJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
        return
    }
    var req struct {
        Email string `json:"email"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Email) == "" {
        sendJSONError(w, http.StatusBadRequest, "Invalid input")
        return
    }
    _, err := db.Exec("UPDATE users SET role_id = 1 WHERE email=$1", req.Email)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to promote user")
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(Response{Status: "success", Message: "User promoted to admin"})
}

func signupPageHandler(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "templates/signup.html")
    logg.WithField("endpoint", "/signup").Info("Served signup.html")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    // Clear the jwt_token cookie by setting an expired cookie.
    cookie := &http.Cookie{
        Name:   "jwt_token",
        Value:  "",
        Path:   "/",
        Expires: time.Unix(0, 0),
        MaxAge: -1,
    }
    http.SetCookie(w, cookie)
    // Redirect to the login page.
    http.Redirect(w, r, "/login-page", http.StatusSeeOther)
}



func getAuthenticatedUser(r *http.Request) (int, int, error) {
    tokenString := ""
    authHeader := r.Header.Get("Authorization")
    if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
        tokenString = strings.TrimPrefix(authHeader, "Bearer ")
    } else {
        if cookie, err := r.Cookie("jwt_token"); err == nil {
            tokenString = cookie.Value
        }
    }

    if tokenString == "" {
        return 0, 0, errors.New("Missing or invalid token")
    }

    claims := jwt.MapClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        return 0, 0, errors.New("Invalid token")
    }

    userID, ok1 := claims["user_id"].(float64)
    roleID, ok2 := claims["role_id"].(float64)
    if !ok1 || !ok2 {
        return 0, 0, errors.New("Invalid token claims")
    }

    return int(userID), int(roleID), nil
}

func getUserInfoFromToken(r *http.Request) (int, int, string, string, error) {
    tokenString := ""
    if cookie, err := r.Cookie("jwt_token"); err == nil {
        tokenString = strings.TrimSpace(cookie.Value)
    } else if authHeader := r.Header.Get("Authorization"); authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
        tokenString = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
    }
    log.Println("Token string:", tokenString)
    if tokenString == "" {
        return 0, 0, "", "", errors.New("Missing or invalid token")
    }
    claims := jwt.MapClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        log.Println("Error parsing token:", err)
        return 0, 0, "", "", errors.New("Invalid token")
    }
    log.Println("Claims:", claims)
    userID, ok1 := claims["user_id"].(float64)
    roleID, ok2 := claims["role_id"].(float64)
    fullName, ok3 := claims["full_name"].(string)
    email, ok4 := claims["email"].(string)
    if !ok1 || !ok2 || !ok3 || !ok4 {
        return 0, 0, "", "", errors.New("Invalid token claims")
    }
    return int(userID), int(roleID), fullName, email, nil
}


//microservice
func sendTransactionToMicroservice(payload interface{}) (*MicroserviceResponse, error) {
    jsonData, err := json.Marshal(payload)
    if err != nil {
        return nil, err
    }
    resp, err := http.Post("http://localhost:8081/transactions", "application/json", bytes.NewReader(jsonData))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("microservice returned status: %d", resp.StatusCode)
    }
    var mResp MicroserviceResponse
    if err := json.NewDecoder(resp.Body).Decode(&mResp); err != nil {
        return nil, err
    }
    return &mResp, nil
}

func purchaseHandler(w http.ResponseWriter, r *http.Request) {
    log.Println("purchaseHandler reached")
    if r.Method != http.MethodPost {
        sendJSONError(w, http.StatusMethodNotAllowed, "Invalid Method")
        return
    }
    var payload struct {
        DrinkID int `json:"drinkId"`
    }
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        sendJSONError(w, http.StatusBadRequest, "Invalid purchase payload")
        return
    }
    var drink Drink
    err := db.QueryRow("SELECT id, name, cost FROM drinks WHERE id = $1", payload.DrinkID).
        Scan(&drink.ID, &drink.Name, &drink.Cost)
    if err != nil {
        sendJSONError(w, http.StatusNotFound, "Drink not found")
        return
    }
    userID, _, fullName, email, err := getUserInfoFromToken(r)
    if err != nil {
        sendJSONError(w, http.StatusUnauthorized, "Missing or invalid token")
        return
    }
    transactionID := int(time.Now().UnixNano() % 10000)
    microPayload := struct {
        CartItems []struct {
            ID       string  `json:"id"`
            Name     string  `json:"name"`
            Price    float64 `json:"price"`
            Quantity int     `json:"quantity"`
        } `json:"cartItems"`
        Customer struct {
            ID    string `json:"id"`
            Name  string `json:"name"`
            Email string `json:"email"`
        } `json:"customer"`
        TransactionID int `json:"transactionId"`
    }{
        TransactionID: transactionID,
    }
    microPayload.CartItems = []struct {
        ID       string  `json:"id"`
        Name     string  `json:"name"`
        Price    float64 `json:"price"`
        Quantity int     `json:"quantity"`
    }{
        {ID: fmt.Sprintf("%d", drink.ID), Name: drink.Name, Price: drink.Cost, Quantity: 1},
    }
    microPayload.Customer.ID = fmt.Sprintf("%d", userID)
    microPayload.Customer.Name = fullName
    microPayload.Customer.Email = email

    msResp, err := sendTransactionToMicroservice(microPayload)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, fmt.Sprintf("Microservice error: %v", err))
        return
    }
    // Instead of doing an HTTP redirect from the server,
    // return the payment URL in JSON.
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "paymentURL": msResp.PaymentURL,
    })
}

//websocket
func handleUserChat(w http.ResponseWriter, r *http.Request) {
    userID, _, fullName, _, err := getUserInfoFromToken(r)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    conn, err := chatUpgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("User chat upgrade error:", err)
        return
    }

    chatID := fmt.Sprintf("chat-%d-%d", userID, time.Now().UnixNano())
    session := &ChatSession{
        ChatID:   chatID,
        UserID:   userID,
        Username: fullName,
        Conn:     conn,
    }
    activeUserChats[userID] = session

    // Load previous chat history
    rows, err := db.Query("SELECT sender, content, timestamp FROM messages WHERE chat_id=$1 ORDER BY timestamp", chatID)
    if err == nil {
        for rows.Next() {
            var msg ChatMessage
            var timestamp time.Time
            if err := rows.Scan(&msg.Username, &msg.Content, &timestamp); err == nil {
                msg.Timestamp = timestamp.Format("15:04:05")
                conn.WriteJSON(msg)
            }
        }
    }
    rows.Close()

    log.Printf("User %s (ID %d) started chat session %s\n", fullName, userID, chatID)

    for {
        var msg ChatMessage
        if err := conn.ReadJSON(&msg); err != nil {
            log.Println("User chat read error:", err)
            delete(activeUserChats, userID)
            break
        }
        msg.Timestamp = time.Now().Format("15:04:05")

        // Save message to database
        _, err = db.Exec("INSERT INTO messages (chat_id, sender, content, timestamp) VALUES ($1, $2, $3, NOW())",
            chatID, msg.Username, msg.Content)
        if err != nil {
            log.Println("Failed to save message:", err)
        }

        // Send to admin if connected
        if activeAdminConn != nil {
            activeAdminConn.WriteJSON(msg)
        }

        // Echo message back to user
        conn.WriteJSON(msg)
    }
}

func handleAdminChat(w http.ResponseWriter, r *http.Request) {
    log.Println("Incoming WebSocket request to admin chat")

    tokenString := r.URL.Query().Get("token")
    if tokenString == "" {
        http.Error(w, "Forbidden: Missing token", http.StatusForbidden)
        return
    }

    claims := jwt.MapClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil || !token.Valid {
        http.Error(w, "Forbidden: Invalid token", http.StatusForbidden)
        return
    }

    roleID, ok := claims["role_id"].(float64)
    if !ok || int(roleID) != 1 {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    conn, err := chatUpgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("Admin chat upgrade error:", err)
        return
    }

    activeAdminConn = conn
    log.Println("Admin connected successfully")

    chatID := r.URL.Query().Get("chatID")

    // Load previous chat history
    rows, err := db.Query("SELECT sender, content, timestamp FROM messages WHERE chat_id=$1 ORDER BY timestamp", chatID)
    if err == nil {
        for rows.Next() {
            var msg ChatMessage
            var timestamp time.Time
            if err := rows.Scan(&msg.Username, &msg.Content, &timestamp); err == nil {
                msg.Timestamp = timestamp.Format("15:04:05")
                conn.WriteJSON(msg)
            }
        }
    }
    rows.Close()

    for {
        var msg ChatMessage
        if err := conn.ReadJSON(&msg); err != nil {
            log.Println("Admin chat read error:", err)
            activeAdminConn = nil
            break
        }
        msg.Timestamp = time.Now().Format("15:04:05")

        // Save message to database
        _, err = db.Exec("INSERT INTO messages (chat_id, sender, content, timestamp) VALUES ($1, $2, $3, NOW())",
            chatID, msg.Username, msg.Content)
        if err != nil {
            log.Println("Failed to save message:", err)
        }

        // Send to all users
        for _, session := range activeUserChats {
            if session.ChatID == chatID {
                session.Conn.WriteJSON(msg)
            }
        }
    }
}

func closeChatHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        sendJSONError(w, http.StatusMethodNotAllowed, "Invalid request method")
        return
    }

    var req struct {
        ChatID string `json:"chatID"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        sendJSONError(w, http.StatusBadRequest, "Invalid JSON request")
        return
    }

    // Delete chat messages from DB
    _, err := db.Exec("DELETE FROM messages WHERE chat_id=$1", req.ChatID)
    if err != nil {
        sendJSONError(w, http.StatusInternalServerError, "Failed to delete chat history")
        return
    }

    // Remove from active chats
    for id, session := range activeUserChats {
        if session.ChatID == req.ChatID {
            delete(activeUserChats, id)
            break
        }
    }

    // Send response
    json.NewEncoder(w).Encode(map[string]bool{"success": true})
}



func getActiveChats() []*ChatSession {
    chats := []*ChatSession{}
    for _, session := range activeUserChats {
        chats = append(chats, session)
    }
    return chats
}



func main() {
    f, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        logg.WithError(err).Fatal("Could not open logs.txt")
    }
    logg.SetFormatter(&logrus.JSONFormatter{})
    logg.SetOutput(f)
    logg.SetLevel(logrus.InfoLevel)
    initDatabase()
    defer db.Close()
    mux := http.NewServeMux()
    mux.HandleFunc("/", getHandler)
    mux.HandleFunc("/index", indexHandler)
    mux.Handle("/userProfile", authMiddleware(http.HandlerFunc(userProfileHandler)))
    mux.HandleFunc("/admin/sendEmail", sendEmailHandler)
    mux.HandleFunc("/user/sendSupportEmail", sendSupportEmailHandler)
    mux.HandleFunc("/post", postHandler)
    mux.HandleFunc("/logout", logoutHandler)
    mux.HandleFunc("/purchase", purchaseHandler)
    mux.HandleFunc("/ws/userChat", handleUserChat)
    mux.HandleFunc("/ws/adminChat", handleAdminChat)
    mux.HandleFunc("/admin/closeChat", closeChatHandler)
    mux.HandleFunc("/drinks", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet {
            getDrinksHandler(w, r)
        } else if r.Method == http.MethodPost {
            createDrinkHandler(w, r)
        } else {
            logg.Warn("Invalid Method for /drinks")
            sendJSONError(w, http.StatusMethodNotAllowed, "Invalid Method")
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
                sendJSONError(w, http.StatusMethodNotAllowed, "Invalid Method")
            }
        } else {
            logg.Warn("Invalid URL for /drinks/")
            sendJSONError(w, http.StatusBadRequest, "Invalid URL")
        }
    })
    mux.HandleFunc("/signup", signupPageHandler)
    mux.HandleFunc("/api/signup", signUpHandler)
    mux.HandleFunc("/verify", verifyHandler)
    mux.HandleFunc("/login-page", loginPageHandler)
    mux.HandleFunc("/login", loginHandler)
    mux.Handle("/admin", authMiddleware(http.HandlerFunc(adminHandler)))
    mux.Handle("/admin-only", authMiddleware(http.HandlerFunc(adminOnlyHandler)))
    mux.Handle("/admin-panel", authMiddleware(http.HandlerFunc(adminPanelHandler)))
    mux.Handle("/admin/promoteUser", authMiddleware(http.HandlerFunc(promoteUserHandler)))
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

