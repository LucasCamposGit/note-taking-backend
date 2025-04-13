package handlers

import (
	"encoding/json"
	"mini-notes/db"
	"mini-notes/models"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func getUserID(r *http.Request) int {
	return r.Context().Value("userID").(int)
}

func GetNotes(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	rows, _ := db.DB.Query("SELECT id, text, parent_id, user_id, created_at FROM notes WHERE parent_id IS NULL AND user_id = ? ORDER BY created_at DESC", userID)
	var notes []models.Note
	for rows.Next() {
		var note models.Note
		rows.Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
		notes = append(notes, note)
	}
	json.NewEncoder(w).Encode(notes)
}

func GetReplies(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	noteID := chi.URLParam(r, "id")
	rows, _ := db.DB.Query("SELECT id, text, parent_id, user_id, created_at FROM notes WHERE parent_id = ? AND user_id = ? ORDER BY created_at ASC", noteID, userID)
	var replies []models.Note
	for rows.Next() {
		var note models.Note
		rows.Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
		replies = append(replies, note)
	}
	json.NewEncoder(w).Encode(replies)
}

func CreateNote(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	var note models.Note

	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	note.UserID = userID
	res, err := db.DB.Exec("INSERT INTO notes (text, parent_id, user_id) VALUES (?, ?, ?)", note.Text, note.ParentID, userID)
	if err != nil {
		http.Error(w, "Failed to insert note", http.StatusInternalServerError)
		return
	}

	lastID, err := res.LastInsertId()
	if err != nil {
		http.Error(w, "Failed to get last insert ID", http.StatusInternalServerError)
		return
	}

	err = db.DB.QueryRow("SELECT id, text, parent_id, user_id, created_at FROM notes WHERE id = ?", lastID).
		Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
	if err != nil {
		http.Error(w, "Failed to fetch created note", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(note)
}

func DeleteNote(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	noteID := chi.URLParam(r, "id")
	res, _ := db.DB.Exec("DELETE FROM notes WHERE id = ? AND user_id = ?", noteID, userID)
	affected, _ := res.RowsAffected()
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": affected})
}

func GetNotesTree(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	rows, err := db.DB.Query(`
		SELECT id, text, parent_id, user_id, created_at
		FROM notes
		WHERE user_id = ?
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		http.Error(w, "Failed to fetch notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	noteMap := make(map[int]*models.Note)
	var allNotes []*models.Note

	for rows.Next() {
		var note models.Note
		err := rows.Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
		if err != nil {
			continue
		}
		note.Replies = []*models.Note{}
		n := note // create copy to avoid pointer issues
		noteMap[n.ID] = &n
		allNotes = append(allNotes, &n)
	}

	var roots []*models.Note

	for _, note := range allNotes {
		if note.ParentID != nil {
			parent, ok := noteMap[*note.ParentID]
			if ok {
				parent.Replies = append(parent.Replies, note)
			}
		} else {
			roots = append(roots, note)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(roots); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}
