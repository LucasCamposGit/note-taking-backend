package middleware

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	return []byte(secret)
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == authHeader {
			log.Printf("Auth Middleware - Bearer prefix missing in token: %s\n", tokenStr)
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		jwtSecret := getJWTSecret()

		// Manual decode of JWT to check structure
		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			log.Printf("Auth Middleware - Invalid token format, missing parts")
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		// Parse the token
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
			return jwtSecret, nil
		})

		if err != nil {
			log.Printf("Aut Middleware - Token parsing error: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

			// Extract user ID from claims
			userID, ok := claims["user_id"].(float64) // JWT numbers are float64 by default
			if !ok {
				log.Printf("Auth Middleware - Missing or invalid user_id in claims")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), "userID", int(userID)))
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}
