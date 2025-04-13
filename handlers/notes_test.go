package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"mini-notes/db"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func setupNotesTest() {
	// Reset notes table
	db.DB.Exec("DELETE FROM notes")

	// Add test notes
	db.DB.Exec("INSERT INTO notes (id, text, parent_id, user_id) VALUES (1, 'Test Note 1', NULL, 1)")
	db.DB.Exec("INSERT INTO notes (id, text, parent_id, user_id) VALUES (2, 'Test Note 2', NULL, 1)")
	db.DB.Exec("INSERT INTO notes (id, text, parent_id, user_id) VALUES (3, 'Test Reply 1', 1, 1)")
	db.DB.Exec("INSERT INTO notes (id, text, parent_id, user_id) VALUES (4, 'Test Note 3', NULL, 2)") // Different user
}

func TestGetNotes(t *testing.T) {
	setupNotesTest()

	// Test case 1: Get all notes for user 1
	t.Run("Get notes for user 1", func(t *testing.T) {
		// Create request
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(GetNotes).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var notes []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &notes)

		// Verify there are 2 top-level notes for user 1
		// (Note 1 and Note 2, excluding the reply and user 2's note)
		if len(notes) != 2 {
			t.Errorf("Expected 2 notes, got %d", len(notes))
		}

		// Check that the notes are for user 1 and have no parent
		for _, note := range notes {
			if int(note["user_id"].(float64)) != 1 {
				t.Errorf("Expected user_id 1, got %v", note["user_id"])
			}
			if note["parent_id"] != nil {
				t.Errorf("Expected parent_id to be nil, got %v", note["parent_id"])
			}
		}
	})

	// Test case 2: Get all notes for user 2
	t.Run("Get notes for user 2", func(t *testing.T) {
		// Create request
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 2)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(GetNotes).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var notes []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &notes)

		// Verify there is 1 note for user 2
		if len(notes) != 1 {
			t.Errorf("Expected 1 note, got %d", len(notes))
		}

		// Check that the note is for user 2
		if len(notes) > 0 {
			if int(notes[0]["user_id"].(float64)) != 2 {
				t.Errorf("Expected user_id 2, got %v", notes[0]["user_id"])
			}
		}
	})

	// Test case 3: No user ID in context
	t.Run("No user ID in context", func(t *testing.T) {
		// Create request without user ID in context
		req, _ := http.NewRequest("GET", "/api/notes", nil)
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(GetNotes).ServeHTTP(rr, req)

		// Check response - should fail
		if status := rr.Code; status == http.StatusOK {
			t.Errorf("Handler should fail without userID in context, got %v", status)
		}
	})
}

func TestCreateNote(t *testing.T) {
	setupNotesTest()

	// Test case 1: Create a top-level note
	t.Run("Create top-level note", func(t *testing.T) {
		// Create request body
		reqBody := map[string]interface{}{
			"text":      "New Test Note",
			"parent_id": nil,
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/notes", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(CreateNote).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var note map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &note)

		// Verify the note was created properly
		if note["text"] != "New Test Note" {
			t.Errorf("Expected text 'New Test Note', got %v", note["text"])
		}
		if note["parent_id"] != nil {
			t.Errorf("Expected parent_id to be nil, got %v", note["parent_id"])
		}
		if int(note["user_id"].(float64)) != 1 {
			t.Errorf("Expected user_id 1, got %v", note["user_id"])
		}
	})

	// Test case 2: Create a reply
	t.Run("Create reply", func(t *testing.T) {
		// Create request body
		reqBody := map[string]interface{}{
			"text":      "New Reply",
			"parent_id": 1,
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/notes", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(CreateNote).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var note map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &note)

		// Verify the note was created properly
		if note["text"] != "New Reply" {
			t.Errorf("Expected text 'New Reply', got %v", note["text"])
		}
		if int(note["parent_id"].(float64)) != 1 {
			t.Errorf("Expected parent_id 1, got %v", note["parent_id"])
		}
		if int(note["user_id"].(float64)) != 1 {
			t.Errorf("Expected user_id 1, got %v", note["user_id"])
		}
	})

	// Test case 3: Reply to non-existent parent
	t.Run("Reply to non-existent parent", func(t *testing.T) {
		// Create request body with non-existent parent ID
		reqBody := map[string]interface{}{
			"text":      "New Reply",
			"parent_id": 999, // Non-existent parent ID
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request
		req, _ := http.NewRequest("POST", "/api/notes", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(CreateNote).ServeHTTP(rr, req)

		// Check response - should fail due to foreign key constraint
		if status := rr.Code; status == http.StatusOK {
			t.Errorf("Handler should fail with non-existent parent ID, got %v", status)
		}
	})

	// Test case 4: No user ID in context
	t.Run("No user ID in context", func(t *testing.T) {
		// Create request body
		reqBody := map[string]interface{}{
			"text": "New Test Note",
		}
		jsonBody, _ := json.Marshal(reqBody)

		// Create request without user ID in context
		req, _ := http.NewRequest("POST", "/api/notes", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		// Call handler
		http.HandlerFunc(CreateNote).ServeHTTP(rr, req)

		// Check response - should fail
		if status := rr.Code; status == http.StatusOK {
			t.Errorf("Handler should fail without userID in context, got %v", status)
		}
	})
}

func TestGetReplies(t *testing.T) {
	setupNotesTest()

	// Test case 1: Get replies for note 1
	t.Run("Get replies for note 1", func(t *testing.T) {
		// Create request
		req, _ := http.NewRequest("GET", "/api/notes/1/replies", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(GetReplies).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var replies []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &replies)

		// Verify there is 1 reply for note 1
		if len(replies) != 1 {
			t.Errorf("Expected 1 reply, got %d", len(replies))
		}

		// Check that the reply has the correct parent_id
		if len(replies) > 0 {
			if int(replies[0]["parent_id"].(float64)) != 1 {
				t.Errorf("Expected parent_id 1, got %v", replies[0]["parent_id"])
			}
		}
	})

	// Test case 2: Get replies for note with no replies
	t.Run("Get replies for note with no replies", func(t *testing.T) {
		// Create request
		req, _ := http.NewRequest("GET", "/api/notes/2/replies", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "2")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(GetReplies).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var replies []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &replies)

		// Verify there are no replies
		if len(replies) != 0 {
			t.Errorf("Expected 0 replies, got %d", len(replies))
		}
	})

	// Test case 3: Get replies for non-existent note
	t.Run("Get replies for non-existent note", func(t *testing.T) {
		// Create request
		req, _ := http.NewRequest("GET", "/api/notes/999/replies", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "999")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(GetReplies).ServeHTTP(rr, req)

		// Check response - should still return 200 OK with empty array
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var replies []map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &replies)

		// Verify there are no replies
		if len(replies) != 0 {
			t.Errorf("Expected 0 replies, got %d", len(replies))
		}
	})
}

func TestDeleteNote(t *testing.T) {
	setupNotesTest()

	// Test case 1: Delete own note
	t.Run("Delete own note", func(t *testing.T) {
		// Create request
		req, _ := http.NewRequest("DELETE", "/api/notes/2", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "2")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(DeleteNote).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var response map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &response)

		// Verify deletion was successful
		if int(response["deleted"].(float64)) != 1 {
			t.Errorf("Expected 1 deletion, got %v", response["deleted"])
		}

		// Verify note is actually deleted
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE id = 2").Scan(&count)
		if count != 0 {
			t.Errorf("Note still exists in database")
		}
	})

	// Test case 2: Delete someone else's note
	t.Run("Delete someone else's note", func(t *testing.T) {
		// Create request to delete note 4 (belongs to user 2)
		req, _ := http.NewRequest("DELETE", "/api/notes/4", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "4")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context (user 1)
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(DeleteNote).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var response map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &response)

		// Verify no deletion occurred
		if int(response["deleted"].(float64)) != 0 {
			t.Errorf("Expected 0 deletions, got %v", response["deleted"])
		}

		// Verify note still exists
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE id = 4").Scan(&count)
		if count != 1 {
			t.Errorf("Note should still exist in database")
		}
	})

	// Test case 3: Delete non-existent note
	t.Run("Delete non-existent note", func(t *testing.T) {
		// Create request to delete note that doesn't exist
		req, _ := http.NewRequest("DELETE", "/api/notes/999", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "999")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(DeleteNote).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var response map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &response)

		// Verify no deletion occurred
		if int(response["deleted"].(float64)) != 0 {
			t.Errorf("Expected 0 deletions, got %v", response["deleted"])
		}
	})

	// Test case 4: Delete note with replies (should cascade delete)
	t.Run("Delete note with replies", func(t *testing.T) {
		// Create request to delete note 1 (which has replies)
		req, _ := http.NewRequest("DELETE", "/api/notes/1", nil)
		rr := httptest.NewRecorder()

		// Setup chi router context with URL param
		chiCtx := chi.NewRouteContext()
		chiCtx.URLParams.Add("id", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))

		// Add user ID to context
		ctx := context.WithValue(req.Context(), "userID", 1)
		req = req.WithContext(ctx)

		// Call handler
		http.HandlerFunc(DeleteNote).ServeHTTP(rr, req)

		// Check response
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Parse response
		var response map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &response)

		// Verify deletion was successful
		if int(response["deleted"].(float64)) != 1 {
			t.Errorf("Expected 1 deletion, got %v", response["deleted"])
		}

		// Verify note is actually deleted
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE id = 1").Scan(&count)
		if count != 0 {
			t.Errorf("Note still exists in database")
		}

		// Verify replies are also deleted
		db.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE parent_id = 1").Scan(&count)
		if count != 0 {
			t.Errorf("Replies still exist in database")
		}
	})
}
