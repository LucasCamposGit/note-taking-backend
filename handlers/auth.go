package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mini-notes/db"
	"mini-notes/models"
	"net/http"
	"os"

	"time"

	"golang.org/x/crypto/bcrypt"

	"log"

	"github.com/golang-jwt/jwt/v5"
)

func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	log.Printf("Getting JWT secret: '%s'", secret)
	return []byte(secret)
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

type authRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type GoogleTokenInfo struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	json.NewDecoder(r.Body).Decode(&req)

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	_, err := db.DB.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", req.Email, hash)
	if err != nil {
		http.Error(w, "User exists or DB error", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	json.NewDecoder(r.Body).Decode(&req)

	var user models.User
	err := db.DB.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", req.Email).Scan(&user.ID, &user.PasswordHash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	claims := Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	log.Printf("Login - Creating token with claims: %+v", claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := getJWTSecret()
	log.Printf("Login - Using JWT Secret: %s", string(jwtSecret))
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Login - Token signing error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Printf("Login - Generated token for user %d: %s...", user.ID, signed[:10])
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse and validate token
	secret := os.Getenv("JWT_SECRET")
	parsedToken, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !parsedToken.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Extract user ID from claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Try to get user_id first (new format)
	var userID int
	if userIDFloat, ok := claims["user_id"].(float64); ok {
		userID = int(userIDFloat)
	} else if subFloat, ok := claims["sub"].(float64); ok {
		// Fallback to sub field (old format)
		userID = int(subFloat)
	} else {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Create new tokens
	expiration := time.Now().Add(24 * time.Hour)
	newClaims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
		},
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)

	jwtSecret := getJWTSecret()
	accessToken, err := newToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	refreshExpiration := time.Now().Add(7 * 24 * time.Hour)
	refreshClaims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiration),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenStr, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Refresh token generation failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshTokenStr,
	})
}
func verifyGoogleToken(token string) (*GoogleTokenInfo, error) {
	log.Printf("Verifying Google token...")

	// Try ID token verification first
	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + token)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			log.Printf("ID token verification failed: status %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			log.Printf("ID token verification request failed: %v", err)
		}

		// Try access token verification
		resp, err = http.Get("https://oauth2.googleapis.com/tokeninfo?access_token=" + token)
		if err != nil {
			log.Printf("Access token verification request failed: %v", err)
			return nil, err
		}
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Google token verification failed with status %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("google token verification failed: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Google token response: %v", err)
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	log.Printf("Google token raw response: %s", string(body))

	var tokenInfo GoogleTokenInfo
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		log.Printf("Failed to parse Google token info: %v", err)
		return nil, err
	}

	log.Printf("Parsed token info: email=%s, verified=%s", tokenInfo.Email, tokenInfo.EmailVerified)

	if tokenInfo.Email == "" || tokenInfo.EmailVerified != "true" {
		log.Printf("Invalid Google user (missing email or not verified)")
		return nil, fmt.Errorf("invalid Google user")
	}

	return &tokenInfo, nil
}

func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling Google login...")

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		log.Printf("Invalid request payload: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	log.Printf("Received token: %s...", req.Token[:12])

	info, err := verifyGoogleToken(req.Token)
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		http.Error(w, "Invalid Google token", http.StatusUnauthorized)
		return
	}

	log.Printf("Verified Google user: %s", info.Email)

	var user models.User
	err = db.DB.QueryRow("SELECT id FROM users WHERE email = ?", info.Email).Scan(&user.ID)
	if err != nil {
		log.Printf("User not found, creating new user: %s", info.Email)
		res, err := db.DB.Exec("INSERT INTO users (email) VALUES (?)", info.Email)
		if err != nil {
			log.Printf("User creation failed: %v", err)
			http.Error(w, "Could not create user", http.StatusInternalServerError)
			return
		}
		id, _ := res.LastInsertId()
		user.ID = int(id)
		log.Printf("Created new user with ID: %d", user.ID)
	} else {
		log.Printf("Found existing user with ID: %d", user.ID)
	}

	// Generate tokens
	expiration := time.Now().Add(24 * time.Hour)
	claims := Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	refreshExpiration := time.Now().Add(7 * 24 * time.Hour)
	refreshClaims := Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiration),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	jwtSecret := getJWTSecret()

	accessStr, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Failed to sign access token: %v", err)
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	refreshStr, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Failed to sign refresh token: %v", err)
		http.Error(w, "Refresh token generation failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Tokens generated successfully for user ID: %d", user.ID)

	json.NewEncoder(w).Encode(map[string]string{
		"token":         accessStr,
		"refresh_token": refreshStr,
	})
}
