package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tebeka/selenium"
)

// TestMain ensures the database is initialized before tests run.
func TestMain(m *testing.M) {
	// Initialize the database connection.
	initDatabase()

	// Run the tests.
	code := m.Run()

	// Close the database when done.
	db.Close()

	os.Exit(code)
}

// Unit Test: TestChunkBase64 checks our base64 chunking function.
func TestChunkBase64(t *testing.T) {
	input := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
	output := chunkBase64(input)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		t.Errorf("Expected 1 line, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "ABCDEFGHIJKLMNOPQRSTUVWXYZ0") {
		t.Errorf("Output does not match expected chunk data: %s", lines[0])
	}

	longInput := strings.Repeat("A", 200)
	longOut := chunkBase64(longInput)
	longLines := strings.Split(strings.TrimSpace(longOut), "\n")
	if len(longLines) != 3 {
		t.Errorf("Expected 3 lines for 200 chars, got %d", len(longLines))
	}
}

// Integration Test: Register a user, verify the account, and then log in.
func TestLoginIntegration(t *testing.T) {
	// Use a unique email address to avoid duplicate key issues.
	uniqueEmail := "test_" + uuid.New().String() + "@example.com"

	// Register a new test user.
	form := SignUpRequest{
		FullName: "Test User",
		Email:    uniqueEmail,
		Password: "arbuz123",
	}
	body, _ := json.Marshal(form)
	req, _ := http.NewRequest("POST", "/api/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	http.HandlerFunc(signUpHandler).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("signUpHandler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	// Simulate user verification for testing purposes.
	_, err := db.Exec("UPDATE users SET is_verified = TRUE WHERE email=$1", uniqueEmail)
	if err != nil {
		t.Fatalf("Failed to verify test user: %v", err)
	}

	// Now attempt login.
	loginForm := LoginRequest{
		Email:    uniqueEmail,
		Password: form.Password,
	}
	loginBody, _ := json.Marshal(loginForm)
	loginReq, _ := http.NewRequest("POST", "/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	rrLogin := httptest.NewRecorder()
	loginHandler(rrLogin, loginReq)
	if rrLogin.Code != http.StatusOK {
		t.Fatalf("loginHandler returned wrong status code: got %v want %v", rrLogin.Code, http.StatusOK)
	}

	// Check that a token is returned.
	var res map[string]string
	if err := json.NewDecoder(rrLogin.Body).Decode(&res); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}
	token, ok := res["token"]
	if !ok || token == "" {
		t.Fatalf("Token not returned in login")
	}
}

//end to end
func TestLoginPageE2E(t *testing.T) {
	// Set up Selenium WebDriver with Chrome in headless mode.
	service, err := selenium.NewRemote(selenium.Capabilities{"browserName": "chrome"}, "http://localhost:4444/wd/hub")
	if err != nil {
		t.Fatalf("Failed to connect to Selenium WebDriver: %v", err)
	}
	defer service.Quit() // Ensure WebDriver quits after the test

	// Open the login page (Using host.docker.internal instead of localhost)
	err = service.Get("http://host.docker.internal:8080/login-page")
	if err != nil {
		t.Fatalf("Failed to load login page: %v", err)
	}
	time.Sleep(2 * time.Second) // Ensure the page loads fully

	// Locate form elements
	emailElem, err := service.FindElement(selenium.ByID, "email")
	if err != nil {
		t.Fatal("Email input not found")
	}
	passwordElem, err := service.FindElement(selenium.ByID, "password")
	if err != nil {
		t.Fatal("Password input not found")
	}
	loginButton, err := service.FindElement(selenium.ByID, "login-button")
	if err != nil {
		t.Fatal("Login button not found")
	}

	// Input login credentials
	emailElem.Clear()
	emailElem.SendKeys("eto_novyi_cadillac@mail.ru")
	passwordElem.Clear()
	passwordElem.SendKeys("arbuz4444")
	loginButton.Click()

	// Wait for redirection
	time.Sleep(3 * time.Second)

	// Verify that user is redirected to user profile
	currentURL, err := service.CurrentURL()
	if err != nil {
		t.Fatalf("Failed to get current URL: %v", err)
	}
	if !strings.Contains(currentURL, "/userProfile") {
		t.Errorf("Expected redirection to /userProfile, got %s", currentURL)
	}
}
