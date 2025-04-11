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
	json.NewDecoder(r.Body).Decode(&note)
	note.UserID = userID
	res, _ := db.DB.Exec("INSERT INTO notes (text, parent_id, user_id) VALUES (?, ?, ?)", note.Text, note.ParentID, userID)
	lastID, _ := res.LastInsertId()
	db.DB.QueryRow("SELECT id, text, parent_id, user_id, created_at FROM notes WHERE id = ?", lastID).Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
	json.NewEncoder(w).Encode(note)
}

func DeleteNote(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	noteID := chi.URLParam(r, "id")
	res, _ := db.DB.Exec("DELETE FROM notes WHERE id = ? AND user_id = ?", noteID, userID)
	affected, _ := res.RowsAffected()
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": affected})
}
