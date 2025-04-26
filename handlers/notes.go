package handlers

import (
	"encoding/json"
	"mini-notes/db"
	"mini-notes/models"
	"net/http"
	"sort"

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

func UpdateNote(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	noteID := chi.URLParam(r, "id")

	var updateData struct {
		Text string `json:"text"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if updateData.Text == "" {
		http.Error(w, "Text field is required", http.StatusBadRequest)
		return
	}

	res, err := db.DB.Exec("UPDATE notes SET text = ? WHERE id = ? AND user_id = ?",
		updateData.Text, noteID, userID)
	if err != nil {
		http.Error(w, "Failed to update note", http.StatusInternalServerError)
		return
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		http.Error(w, "Note not found or you don't have permission to update it", http.StatusNotFound)
		return
	}

	var note models.Note
	err = db.DB.QueryRow("SELECT id, text, parent_id, user_id, created_at FROM notes WHERE id = ?", noteID).
		Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
	if err != nil {
		http.Error(w, "Failed to fetch updated note", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(note)
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
		n := note
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

	var sortReplies func(notes []*models.Note)
	sortReplies = func(notes []*models.Note) {
		for _, note := range notes {
			if len(note.Replies) > 0 {
				sort.SliceStable(note.Replies, func(i, j int) bool {
					return note.Replies[i].CreatedAt.Before(note.Replies[j].CreatedAt)
				})
				sortReplies(note.Replies)
			}
		}
	}
	sortReplies(roots)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(roots); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

func GetNoteWithRelated(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	noteID := chi.URLParam(r, "id")

	// First get the requested note
	var targetNote models.Note
	err := db.DB.QueryRow("SELECT id, text, parent_id, user_id, created_at FROM notes WHERE id = ? AND user_id = ?",
		noteID, userID).Scan(&targetNote.ID, &targetNote.Text, &targetNote.ParentID, &targetNote.UserID, &targetNote.CreatedAt)

	if err != nil {
		http.Error(w, "Note not found", http.StatusNotFound)
		return
	}

	// Get all notes from this user to build the relationship tree
	rows, err := db.DB.Query(`
		SELECT id, text, parent_id, user_id, created_at
		FROM notes
		WHERE user_id = ?
	`, userID)
	if err != nil {
		http.Error(w, "Failed to fetch notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Create a map of all notes and a slice to hold them
	noteMap := make(map[int]*models.Note)
	var allNotes []*models.Note

	for rows.Next() {
		var note models.Note
		err := rows.Scan(&note.ID, &note.Text, &note.ParentID, &note.UserID, &note.CreatedAt)
		if err != nil {
			continue
		}
		note.Replies = []*models.Note{}
		n := note
		noteMap[n.ID] = &n
		allNotes = append(allNotes, &n)
	}

	// Build the relationship structure
	for _, note := range allNotes {
		if note.ParentID != nil {
			parent, ok := noteMap[*note.ParentID]
			if ok {
				parent.Replies = append(parent.Replies, note)
			}
		}
	}

	// Sort all replies by creation time
	var sortReplies func(notes []*models.Note)
	sortReplies = func(notes []*models.Note) {
		for _, note := range notes {
			if len(note.Replies) > 0 {
				sort.SliceStable(note.Replies, func(i, j int) bool {
					return note.Replies[i].CreatedAt.Before(note.Replies[j].CreatedAt)
				})
				sortReplies(note.Replies)
			}
		}
	}

	// Find the root note - either the target note if it's a parent
	// or the parent of the target note if it's a child
	var rootNote *models.Note
	if targetNote.ParentID == nil {
		// Target note is a parent, so it's the root
		rootNote = noteMap[targetNote.ID]
	} else {
		// Target note is a child, so find its parent as the root
		rootNote = noteMap[*targetNote.ParentID]
	}

	// Sort the replies
	if rootNote != nil {
		sortReplies([]*models.Note{rootNote})
	} else {
		// If we somehow couldn't find the root, just return the target note
		rootNote = noteMap[targetNote.ID]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rootNote); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}
