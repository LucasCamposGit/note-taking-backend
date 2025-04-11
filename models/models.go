package models

import "time"

type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Note struct {
	ID        int        `json:"id"`
	Text      string     `json:"text"`
	ParentID  *int       `json:"parent_id"`
	UserID    int        `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
}
