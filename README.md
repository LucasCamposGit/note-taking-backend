# Note-Taking Backend

A RESTful backend service for a note-taking application, built with Go. This backend provides user authentication, note management, and threaded replies functionality.

## Features

- **User Authentication**
  - Email/password registration and login
  - Google OAuth integration
  - JWT-based authentication
  - Token refresh mechanism

- **Notes Management**
  - Create, read, and delete notes
  - Hierarchical notes with reply support
  - User-specific note isolation

## Tech Stack

- **Language**: Go (Golang)
- **Web Framework**: Chi router
- **Database**: MySQL
- **Authentication**: JWT, bcrypt for password hashing
- **Environment**: Environment variables via .env file

## API Documentation

### Authentication Endpoints

#### Register
- **URL**: `/api/register`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**: `201 Created` on success

#### Login
- **URL**: `/api/login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "token": "jwt_token_here"
  }
  ```

#### Refresh Token
- **URL**: `/api/refresh-token`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "refresh_token": "refresh_token_here"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "new_access_token_here",
    "refresh_token": "new_refresh_token_here"
  }
  ```

#### Google Login
- **URL**: `/api/google-login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "token": "google_access_token_here"
  }
  ```
- **Response**:
  ```json
  {
    "token": "jwt_access_token_here",
    "refresh_token": "jwt_refresh_token_here"
  }
  ```

### Notes Endpoints (Protected Routes)

All notes endpoints require the `Authorization: Bearer {token}` header.

#### Get All Notes
- **URL**: `/api/notes`
- **Method**: `GET`
- **Response**: Array of notes
  ```json
  [
    {
      "id": 1,
      "text": "Note content",
      "parent_id": null,
      "user_id": 1,
      "created_at": "2023-01-01T12:00:00Z"
    }
  ]
  ```

#### Create Note
- **URL**: `/api/notes`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "text": "Note content",
    "parent_id": null
  }
  ```
- **Response**: Created note object

#### Get Replies for a Note
- **URL**: `/api/notes/{id}/replies`
- **Method**: `GET`
- **Response**: Array of reply notes
  ```json
  [
    {
      "id": 2,
      "text": "Reply content",
      "parent_id": 1,
      "user_id": 1,
      "created_at": "2023-01-01T12:30:00Z"
    }
  ]
  ```

#### Delete Note
- **URL**: `/api/notes/{id}`
- **Method**: `DELETE`
- **Response**:
  ```json
  {
    "deleted": 1
  }
  ```

#### Update Note
- **URL**: `/api/notes/{id}`
- **Method**: `PATCH`
- **Request Body**:
  ```json
  {
    "text": "Updated note content"
  }
  ```
- **Response**: Updated note object
  ```json
  {
    "id": 1,
    "text": "Updated note content",
    "parent_id": null,
    "user_id": 1,
    "created_at": "2023-01-01T12:00:00Z"
  }
  ```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Notes Table
```sql
CREATE TABLE notes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  text TEXT NOT NULL,
  parent_id INT,
  user_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_id) REFERENCES notes(id) ON DELETE CASCADE
);
```

## Setup and Installation

### Prerequisites
- Go 1.16+
- MySQL database

### Configuration
1. Clone the repository
2. Create a `.env` file in the root directory with the following variables:
   ```
   DSN=user:password@tcp(localhost:3306)/notesdb?parseTime=true
   JWT_SECRET=your_jwt_secret_key
   ```

### Database Setup
The application automatically creates the required tables when started.

### Running the Server
```bash
# Install dependencies
go mod download

# Run the server
go run main.go
```

The server will start on http://localhost:3002

## Development

### Project Structure
- `/db`: Database connection and setup
- `/handlers`: Request handlers for API endpoints
- `/middleware`: Middleware functions including authentication
- `/models`: Data models and structures
- `main.go`: Entry point and server configuration

## Security Considerations
- Passwords are hashed using bcrypt
- Authentication is handled via JWT tokens
- CORS headers are properly configured
- User data is isolated by user ID

## Authentication System Deep Dive

### System Architecture

The authentication system is built with security and flexibility in mind, providing both traditional email/password authentication and Google OAuth integration using a stateless JWT-based approach.

### 1. JWT-Based Authentication Flow

The system implements stateless authentication using JSON Web Tokens (JWT):

- **Token Structure**: Tokens contain a `user_id` claim and an expiration time (`exp`).
- **Token Generation**: When users log in, a signed JWT is created using the `JWT_SECRET` environment variable.
- **Token Verification**: Protected endpoints validate tokens via middleware before processing requests.
- **Token Lifecycle**: Access tokens expire after 24 hours, and refresh tokens last 7 days.

### 2. Authentication Handlers

#### a. User Registration (`Register`)
```go
func Register(w http.ResponseWriter, r *http.Request) {
    // Parse email/password from request
    // Hash password with bcrypt
    // Store user in database
}
```
- Securely hashes passwords using bcrypt before storage
- Returns 201 Created on success, 400 Bad Request if user exists

#### b. Traditional Login (`Login`)
```go
func Login(w http.ResponseWriter, r *http.Request) {
    // Parse credentials
    // Verify against database
    // Generate and return JWT token
}
```
- Retrieves user record by email
- Verifies password hash using bcrypt
- Generates JWT with user_id claim and 24-hour expiration
- Returns token in JSON response

#### c. Google Authentication (`GoogleLogin`)
```go
func GoogleLogin(w http.ResponseWriter, r *http.Request) {
    // Verify Google token
    // Create or retrieve user account
    // Generate and return JWT tokens
}
```
- Verifies Google access token against Google's tokeninfo endpoint
- Creates a new user if email not found in database
- Issues identical JWT format as regular login

#### d. Token Refresh (`RefreshToken`)
```go
func RefreshToken(w http.ResponseWriter, r *http.Request) {
    // Verify refresh token
    // Extract user ID
    // Issue new access and refresh tokens
}
```
- Handles both token formats (supporting backward compatibility)
- Creates new tokens with updated expiration times

### 3. Authentication Middleware

The `RequireAuth` middleware in `middleware/auth.go` provides protection for routes:

```go
func RequireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from Authorization header
        // Verify token signature and validity
        // Add user ID to request context
        // Proceed to next handler
    })
}
```

- Extracts JWT from Bearer token in Authorization header
- Validates token signature using the same secret used for token creation
- Places user ID in request context for downstream handlers
- Returns 401 Unauthorized for invalid/expired tokens

### 4. Key Technical Details

#### JWT Implementation

- **Library**: Uses `github.com/golang-jwt/jwt/v5` for JWT operations
- **Claims Structure**: Custom `Claims` struct with `UserID` field
- **Token Verification**: Runtime verification that prevents timing issues with environment variables

#### Security Considerations

- **Password Storage**: Passwords are never stored in plaintext, only bcrypt hashes
- **Token Expiration**: Short-lived access tokens (24 hours) mitigate risks from token theft
- **Google Verification**: Confirms email ownership and verification status before creating accounts

#### API Protection

The main.go file establishes route groups:
```go
r.Group(func(r chi.Router) {
    r.Use(appmw.RequireAuth)
    r.Get("/api/notes", handlers.GetNotes)
    r.Post("/api/notes", handlers.CreateNote)
    // ...other protected endpoints
})
```

All note operations require a valid authenticated session.

### 5. Runtime Authentication Flow

1. Client logs in via email/password or Google OAuth
2. Server generates and returns a JWT 
3. Client stores token and includes it in Authorization header for subsequent requests
4. Middleware validates token before allowing access to protected endpoints
5. When token expires, client uses refresh token to obtain new credentials

### 6. Debugging Authentication Issues

- **Secret Verification**: Ensure the JWT_SECRET is loaded properly at runtime
- **Token Format**: All tokens use the unified Claims structure with `user_id` field
- **Authorization Header**: Must use format `Authorization: Bearer <token>`
- **Error Response**: 401 Unauthorized is returned for any authentication failure

This authentication system provides a secure, stateless approach that scales well and supports multiple authentication methods while maintaining consistent token handling throughout the application.

## Testing

The application includes a comprehensive test suite to ensure functionality and identify regressions:

### Test Organization

- **Unit Tests**: Individual tests for handler functions and middleware
- **Integration Tests**: End-to-end tests that verify the complete user journey

### Test Types

1. **Authentication Tests** (`handlers/auth_test.go`)
   - Registration validation
   - Login credential verification
   - Token generation and verification
   - Refresh token functionality

2. **Middleware Tests** (`middleware/auth_test.go`)
   - Token extraction and validation
   - Authorization header parsing
   - User context propagation
   - Error handling for invalid tokens

3. **Notes API Tests** (`handlers/notes_test.go`)
   - Note creation
   - Hierarchical note relationships
   - User-specific note isolation
   - Deletion and cascade operations

4. **Integration Tests** (`integration_test.go`)
   - Complete user journey from registration to login
   - JWT-based API access
   - Note creation, retrieval, and deletion
   - Security boundary testing

### Running Tests

```bash
# Create a test database
mysql -u root -e "CREATE DATABASE notes_test_db"

# Run all tests
go test ./...

# Run specific test files
go test ./handlers/auth_test.go
go test ./middleware/auth_test.go

# Run with verbose output
go test -v ./...
```

### Test Environment

Tests use a separate `.env.test` configuration file to prevent interference with the production database.

## License
[MIT License](LICENSE) 