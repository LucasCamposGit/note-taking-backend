package middleware

import (
	"context"
	"mini-notes/handlers"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.ParseWithClaims(tokenStr, &handlers.Claims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte("your-secret"), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims := token.Claims.(*handlers.Claims)
		r = r.WithContext(context.WithValue(r.Context(), "userID", claims.UserID))
		next.ServeHTTP(w, r)
	})
}
