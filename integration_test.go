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

	// Create test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.DefaultCost)
	db.DB.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", testUserEmail, hashedPassword)

	// Setup router
	router = chi.NewRouter()
	router.Post("/api/register", handlers.Register)
	router.Post("/api/login", handlers.Login)
	router.Post("/api/refresh-token", handlers.RefreshToken)
	router.Post("/api/google-login", handlers.GoogleLogin)

	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/notes", handlers.GetNotes)
		r.Get("/api/notes/{id}/replies", handlers.GetReplies)
		r.Get("/api/notes/tree", handlers.GetNotesTree)
		r.Post("/api/notes", handlers.CreateNote)
		r.Patch("/api/notes/{id}", handlers.UpdateNote)
		r.Delete("/api/notes/{id}", handlers.DeleteNote)
	})

	// Get authentication token for test user
	loginBody, _ := json.Marshal(map[string]string{
		"email":    testUserEmail,
		"password": testUserPassword,
	})
	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var loginResp map[string]string
	json.Unmarshal(resp.Body.Bytes(), &loginResp)
	accessToken = loginResp["token"]
}

func TestMain(m *testing.M) {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file, using default values")
	}

	// Initialize database
	db.ConnectDB()

	// Setup test environment
	setupIntegrationTest()

	// Run tests
	code := m.Run()

	// Clean up
	db.DB.Exec("DROP TABLE IF EXISTS notes")
	db.DB.Exec("DROP TABLE IF EXISTS users")

	os.Exit(code)
}

func TestCreateAndGetNote(t *testing.T) {
	// Create a note
	noteBody, _ := json.Marshal(map[string]interface{}{
		"text":      "Integration Test Note",
		"parent_id": nil,
	})

	req := httptest.NewRequest("POST", "/api/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Code)
	}

	var createdNote map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &createdNote)
	noteID := int(createdNote["id"].(float64))

	// Get the notes
	req = httptest.NewRequest("GET", "/api/notes", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Code)
	}

	var notes []map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &notes)

	found := false
	for _, note := range notes {
		if int(note["id"].(float64)) == noteID {
			found = true
			break
		}
	}

	if !found {
		t.Error("Created note not found in the list of notes")
	}
}

func TestUpdateNote(t *testing.T) {
	// Create a note first
	noteBody, _ := json.Marshal(map[string]interface{}{
		"text":      "Note to be updated",
		"parent_id": nil,
	})

	req := httptest.NewRequest("POST", "/api/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var createdNote map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &createdNote)
	noteID := int(createdNote["id"].(float64))

	// Update the note
	updateBody, _ := json.Marshal(map[string]string{
		"text": "Updated integration test note",
	})

	req = httptest.NewRequest("PATCH", "/api/notes/"+string(noteID), bytes.NewBuffer(updateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Code)
	}

	var updatedNote map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &updatedNote)

	if updatedNote["text"] != "Updated integration test note" {
		t.Errorf("Expected updated text, got %v", updatedNote["text"])
	}

	// Verify the note was updated by fetching it
	req = httptest.NewRequest("GET", "/api/notes", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var notes []map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &notes)

	found := false
	for _, note := range notes {
		if int(note["id"].(float64)) == noteID {
			found = true
			if note["text"] != "Updated integration test note" {
				t.Errorf("Note was not correctly updated in database, got text: %v", note["text"])
			}
			break
		}
	}

	if !found {
		t.Error("Updated note not found in the list of notes")
	}
}
