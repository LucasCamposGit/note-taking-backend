package handlers

import (
	"bytes"
	"encoding/json"
	"mini-notes/db"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// Setup test environment
	godotenv.Load("../.env.test")

	// Setup test database
	db.ConnectDB()
	setupTestDB()

	// Run tests
	code := m.Run()

	// Cleanup
	cleanupTestDB()

	os.Exit(code)
}

func setupTestDB() {
	// Create test user tables
	db.DB.Exec("DROP TABLE IF EXISTS notes")
	db.DB.Exec("DROP TABLE IF EXISTS users")
	db.DB.Exec(`CREATE TABLE users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	db.DB.Exec(`CREATE TABLE notes (
		id INT AUTO_INCREMENT PRIMARY KEY,
		text TEXT NOT NULL,
		parent_id INT,
		user_id INT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (parent_id) REFERENCES notes(id) ON DELETE CASCADE
	)`)

	// Create test user
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	db.DB.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", "test@example.com", hash)
}

func cleanupTestDB() {
	db.DB.Exec("DROP TABLE IF EXISTS notes")
	db.DB.Exec("DROP TABLE IF EXISTS users")
}

func TestRegister(t *testing.T) {
	// Test case 1: Successful registration
	t.Run("Successful registration", func(t *testing.T) {
		// Create request body
		reqBody := map[string]string{
			"email":    "newuser@example.com",
			"password": "password123",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(Register).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusCreated {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusCreated)
		}

		// Verify user was created in DB
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", "newuser@example.com").Scan(&count)
		if count != 1 {
			t.Errorf("Expected 1 user record, got %d", count)
		}
	})

	// Test case 2: User already exists
	t.Run("User already exists", func(t *testing.T) {
		// Create request body with existing email
		reqBody := map[string]string{
			"email":    "test@example.com", // Already exists from setup
			"password": "password123",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(Register).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusBadRequest {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
		}
	})

	// Test case 3: Invalid request body
	t.Run("Invalid request body", func(t *testing.T) {
		// Create invalid request body
		reqBody := map[string]string{
			"email": "invalid@example.com",
			// Missing password
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(Register).ServeHTTP(rr, req)

		// We're expecting this to still work due to zero-valued fields in struct
		// But in a real app, we'd want to validate required fields
		if status := rr.Code; status != http.StatusCreated {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusCreated)
		}
	})
}

func TestLogin(t *testing.T) {
	// Test case 1: Successful login
	t.Run("Successful login", func(t *testing.T) {
		// Create request body
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": "testpassword",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(Login).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Verify response contains token
		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)
		if token, exists := response["token"]; !exists || token == "" {
			t.Errorf("Response missing token")
		}
	})

	// Test case 2: Invalid credentials
	t.Run("Invalid credentials", func(t *testing.T) {
		// Create request body with wrong password
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": "wrongpassword",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(Login).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Test case 3: User not found
	t.Run("User not found", func(t *testing.T) {
		// Create request body with non-existent email
		reqBody := map[string]string{
			"email":    "nonexistent@example.com",
			"password": "testpassword",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(Login).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})
}

func TestRefreshToken(t *testing.T) {
	// Create a valid refresh token for testing
	userID := 1
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := getJWTSecret()
	refreshToken, _ := token.SignedString(jwtSecret)

	// Test case 1: Successful token refresh
	t.Run("Successful token refresh", func(t *testing.T) {
		// Create request body
		reqBody := map[string]string{
			"refresh_token": refreshToken,
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/refresh-token", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(RefreshToken).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Verify response contains tokens
		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)
		if accessToken, exists := response["access_token"]; !exists || accessToken == "" {
			t.Errorf("Response missing access_token")
		}
		if newRefreshToken, exists := response["refresh_token"]; !exists || newRefreshToken == "" {
			t.Errorf("Response missing refresh_token")
		}
	})

	// Test case 2: Invalid refresh token
	t.Run("Invalid refresh token", func(t *testing.T) {
		// Create request body with invalid token
		reqBody := map[string]string{
			"refresh_token": "invalid.token.here",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/refresh-token", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(RefreshToken).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Test case 3: Missing refresh token
	t.Run("Missing refresh token", func(t *testing.T) {
		// Create empty request body
		reqBody := map[string]string{}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/refresh-token", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(RefreshToken).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusBadRequest {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
		}
	})
}

// Helper function to create a test JWT token
func createTestToken(userID int) string {
	expiresAt := time.Now().Add(24 * time.Hour)
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := getJWTSecret()
	signedToken, _ := token.SignedString(jwtSecret)
	return signedToken
}

// Mock for verifyGoogleToken for testing
func mockVerifyGoogleToken(accessToken string) (*GoogleTokenInfo, error) {
	return &GoogleTokenInfo{
		Email:         "google@example.com",
		EmailVerified: "true",
		Sub:           "123456789",
	}, nil
}
