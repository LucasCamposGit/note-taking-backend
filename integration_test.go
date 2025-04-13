package main

import (
	"bytes"
	"encoding/json"
	"log"
	"mini-notes/db"
	"mini-notes/handlers"
	"mini-notes/middleware"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var router *chi.Mux
var testUserEmail = "integration@example.com"
var testUserPassword = "integration123"
var accessToken string

func setupIntegrationTest() {
	// Setup test database
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
}

func TestMain(m *testing.M) {
	// Setup
	err := godotenv.Load(".env.test")
	if err != nil {
		log.Fatal("Error loading .env.test file")
	}

	// Connect to database
	db.ConnectDB()
	setupIntegrationTest()

	// Setup router with all endpoints
	router = chi.NewRouter()
	router.Post("/api/register", handlers.Register)
	router.Post("/api/login", handlers.Login)
	router.Post("/api/refresh-token", handlers.RefreshToken)
	router.Post("/api/google-login", handlers.GoogleLogin)

	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/notes", handlers.GetNotes)
		r.Get("/api/notes/{id}/replies", handlers.GetReplies)
		r.Post("/api/notes", handlers.CreateNote)
		r.Delete("/api/notes/{id}", handlers.DeleteNote)
	})

	// Run tests
	code := m.Run()

	// Cleanup
	db.DB.Exec("DROP TABLE IF EXISTS notes")
	db.DB.Exec("DROP TABLE IF EXISTS users")

	os.Exit(code)
}

func TestFullUserJourney(t *testing.T) {
	// Step 1: Register a new user
	t.Run("1. Register user", func(t *testing.T) {
		reqBody := map[string]string{
			"email":    testUserEmail,
			"password": testUserPassword,
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusCreated {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusCreated)
		}

		// Verify user was created
		var user struct {
			ID           int
			Email        string
			PasswordHash string
		}
		err := db.DB.QueryRow("SELECT id, email, password_hash FROM users WHERE email = ?", testUserEmail).Scan(&user.ID, &user.Email, &user.PasswordHash)
		if err != nil {
			t.Errorf("Failed to find registered user: %v", err)
		}

		// Verify password was hashed
		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(testUserPassword))
		if err != nil {
			t.Errorf("Password was not hashed correctly: %v", err)
		}
	})

	// Step 2: Login with the registered user
	t.Run("2. Login user", func(t *testing.T) {
		reqBody := map[string]string{
			"email":    testUserEmail,
			"password": testUserPassword,
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response and save token for future requests
		var response map[string]string
		json.Unmarshal(rr.Body.Bytes(), &response)

		if token, exists := response["token"]; !exists || token == "" {
			t.Errorf("Response missing token")
		} else {
			accessToken = token
		}
	})

	// Step 3: Create a note (authenticated)
	var noteID int
	t.Run("3. Create note", func(t *testing.T) {
		reqBody := map[string]string{
			"text": "Integration Test Note",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", "/api/notes", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response to get note ID
		var note map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &note)

		if id, ok := note["id"].(float64); ok {
			noteID = int(id)
		} else {
			t.Errorf("Failed to get note ID from response")
		}

		// Verify note content
		if note["text"] != "Integration Test Note" {
			t.Errorf("Note text doesn't match: got %v want %v", note["text"], "Integration Test Note")
		}
	})

	// Step 4: Create a reply to the note
	var replyID int
	t.Run("4. Create reply", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"text":      "Reply to Integration Test Note",
			"parent_id": noteID,
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", "/api/notes", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response to get reply ID
		var reply map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &reply)

		if id, ok := reply["id"].(float64); ok {
			replyID = int(id)
		} else {
			t.Errorf("Failed to get reply ID from response")
		}

		// Verify reply content and parent
		if reply["text"] != "Reply to Integration Test Note" {
			t.Errorf("Reply text doesn't match: got %v want %v", reply["text"], "Reply to Integration Test Note")
		}
		if int(reply["parent_id"].(float64)) != noteID {
			t.Errorf("Reply parent_id doesn't match: got %v want %v", reply["parent_id"], noteID)
		}
	})

	// Step 5: Get all notes
	t.Run("5. Get all notes", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var notes []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &notes)

		// Verify we have 1 top-level note (not including the reply)
		if len(notes) != 1 {
			t.Errorf("Expected 1 note, got %d", len(notes))
		}

		// Verify note content
		if len(notes) > 0 {
			if int(notes[0]["id"].(float64)) != noteID {
				t.Errorf("Note ID doesn't match: got %v want %v", notes[0]["id"], noteID)
			}
			if notes[0]["text"] != "Integration Test Note" {
				t.Errorf("Note text doesn't match: got %v want %v", notes[0]["text"], "Integration Test Note")
			}
		}
	})

	// Step 6: Get replies for the note
	t.Run("6. Get replies", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/notes/"+string(rune(noteID))+"/replies", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var replies []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &replies)

		// Verify we have 1 reply
		if len(replies) != 1 {
			t.Errorf("Expected 1 reply, got %d", len(replies))
		}

		// Verify reply content
		if len(replies) > 0 {
			if int(replies[0]["id"].(float64)) != replyID {
				t.Errorf("Reply ID doesn't match: got %v want %v", replies[0]["id"], replyID)
			}
			if replies[0]["text"] != "Reply to Integration Test Note" {
				t.Errorf("Reply text doesn't match: got %v want %v", replies[0]["text"], "Reply to Integration Test Note")
			}
			if int(replies[0]["parent_id"].(float64)) != noteID {
				t.Errorf("Reply parent_id doesn't match: got %v want %v", replies[0]["parent_id"], noteID)
			}
		}
	})

	// Step 7: Delete the reply
	t.Run("7. Delete reply", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/notes/"+string(rune(replyID)), nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Verify deletion
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE id = ?", replyID).Scan(&count)
		if count != 0 {
			t.Errorf("Reply still exists in database after deletion")
		}
	})

	// Step 8: Delete the note
	t.Run("8. Delete note", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/notes/"+string(rune(noteID)), nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Verify deletion
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE id = ?", noteID).Scan(&count)
		if count != 0 {
			t.Errorf("Note still exists in database after deletion")
		}
	})

	// Step 9: Attempt to access with invalid token
	t.Run("9. Invalid token access", func(t *testing.T) {
		// Create an invalid token by modifying one character
		invalidToken := accessToken[:len(accessToken)-1] + "X"

		req, _ := http.NewRequest("GET", "/api/notes", nil)
		req.Header.Set("Authorization", "Bearer "+invalidToken)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		// Should receive unauthorized response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})

	// Step 10: Attempt to access without token
	t.Run("10. No token access", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		// Should receive unauthorized response
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
	})
}
