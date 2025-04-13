package middleware

import (
	"mini-notes/handlers"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

func TestMain(m *testing.M) {
	// Setup test environment
	godotenv.Load("../.env.test")

	// Run tests
	code := m.Run()

	os.Exit(code)
}

func createTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract userID from context and write it to response
		userID, ok := r.Context().Value("userID").(int)
		if !ok {
			http.Error(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User ID: " + string(rune(userID))))
	})
}

func createTestToken(userID int) string {
	expiresAt := time.Now().Add(24 * time.Hour)
	claims := handlers.Claims{
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

func createExpiredToken(userID int) string {
	expiresAt := time.Now().Add(-24 * time.Hour) // Expired 1 day ago
	claims := handlers.Claims{
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

func TestRequireAuth(t *testing.T) {
	// Test case 1: Valid token
	t.Run("Valid token", func(t *testing.T) {
		// Create test handler with middleware
		testHandler := createTestHandler()
		handler := RequireAuth(testHandler)

		// Create request with valid token
		userID := 1
		token := createTestToken(userID)
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Call handler
		handler.ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
	})

	// Test case 2: Missing Authorization header
	t.Run("Missing Authorization header", func(t *testing.T) {
		// Create test handler with middleware
		testHandler := createTestHandler()
		handler := RequireAuth(testHandler)

		// Create request without token
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		rr := httptest.NewRecorder()

		// Call handler
		handler.ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Test case 3: Invalid token format
	t.Run("Invalid token format", func(t *testing.T) {
		// Create test handler with middleware
		testHandler := createTestHandler()
		handler := RequireAuth(testHandler)

		// Create request with invalid token
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "InvalidToken")
		rr := httptest.NewRecorder()

		// Call handler
		handler.ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Test case 4: Expired token
	t.Run("Expired token", func(t *testing.T) {
		// Create test handler with middleware
		testHandler := createTestHandler()
		handler := RequireAuth(testHandler)

		// Create request with expired token
		userID := 1
		token := createExpiredToken(userID)
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Call handler
		handler.ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Test case 5: Token with wrong signature
	t.Run("Token with wrong signature", func(t *testing.T) {
		// Create test handler with middleware
		testHandler := createTestHandler()
		handler := RequireAuth(testHandler)

		// Create request with tampered token
		// Get a valid token and modify the signature
		validToken := createTestToken(1)
		parts := strings.Split(validToken, ".")
		if len(parts) != 3 {
			t.Fatalf("Invalid token format")
		}

		// Modify the last character of the signature
		tamperedToken := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + "X"

		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "Bearer "+tamperedToken)
		rr := httptest.NewRecorder()

		// Call handler
		handler.ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Test case 6: Context propagation
	t.Run("Context propagation", func(t *testing.T) {
		// Create a custom test handler that checks context
		contextTestHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value("userID").(int)
			if !ok {
				t.Errorf("userID not found in request context")
				http.Error(w, "User ID not found in context", http.StatusInternalServerError)
				return
			}

			if userID != 42 {
				t.Errorf("userID in context: got %v want %v", userID, 42)
			}

			w.WriteHeader(http.StatusOK)
		})

		// Create middleware wrapped handler
		handler := RequireAuth(contextTestHandler)

		// Create request with valid token for user ID 42
		token := createTestToken(42)
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Call handler
		handler.ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
	})
}
