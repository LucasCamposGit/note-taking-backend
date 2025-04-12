package main

import (
	"log"
	"mini-notes/db"
	"mini-notes/handlers"
	appmw "mini-notes/middleware"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}


	db.ConnectDB()
	r := chi.NewRouter()

	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	

	r.Post("/api/register", handlers.Register)
	r.Post("/api/login", handlers.Login)
	r.Post("/api/refresh-token", handlers.RefreshToken)
	r.Post("/api/google-login", handlers.GoogleLogin)
	
	r.Group(func(r chi.Router) {
		r.Use(appmw.RequireAuth)
		r.Get("/api/notes", handlers.GetNotes)
		r.Get("/api/notes/{id}/replies", handlers.GetReplies)
		r.Post("/api/notes", handlers.CreateNote)
		r.Delete("/api/notes/{id}", handlers.DeleteNote)
	})

	log.Println("Server running on http://localhost:3002")
	http.ListenAndServe(":3002", r)
}
