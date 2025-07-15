package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// Session store with a mutex for thread safety
var sessions = make(map[string]time.Time)
var sessionMutex sync.RWMutex

// Global database connection pool
var db *sql.DB

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

type JobPosting struct {
	ID             int            `json:"id"`
	Title          sql.NullString `json:"title"`
	Link           string         `json:"link"` // Link is a key and should not be null
	Snippet        sql.NullString `json:"snippet"`
	DatePosted     sql.NullString `json:"date_posted"`
	CompanyName    sql.NullString `json:"company_name"`
	Location       sql.NullString `json:"location"`
	Description    sql.NullString `json:"description"`
	EmploymentType sql.NullString `json:"employment_type"`
	DateUpdated    sql.NullTime   `json:"dateupdated"`
}

// writeJSONError is a helper to send consistent JSON-formatted error messages.
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(AuthResponse{
		Success: false,
		Message: message,
	})
}

// initDB initializes the database connection
func initDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	log.Println("Successfully connected to the database!")
}

func main() {
	initDB() // Initialize the database connection
	// FIX: Run session cleanup in a single, periodic background goroutine
	go startSessionCleanup()

	http.HandleFunc("/auth/login", loginHandler)
	http.HandleFunc("/auth/verify", verifyHandler)
	http.HandleFunc("/jobs", getJobsHandler) // Add route for fetching jobs
	http.HandleFunc("/", corsAnywhereHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting authenticated proxy server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// getJobsHandler fetches job postings from the database.
func getJobsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// The query remains the same
	rows, err := db.Query("SELECT id, title, link, snippet, date_posted, company_name, location, description, employment_type, dateupdated FROM job_postings")
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var jobs []JobPosting
	for rows.Next() {
		var job JobPosting
		// The scan targets are now pointers to fields that can handle NULLs
		if err := rows.Scan(&job.ID, &job.Title, &job.Link, &job.Snippet, &job.DatePosted, &job.CompanyName, &job.Location, &job.Description, &job.EmploymentType, &job.DateUpdated); err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		jobs = append(jobs, job)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jobs); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func startSessionCleanup() {

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cleanupSessions()
	}
}

func cleanupSessions() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	deletedCount := 0
	for token, expiry := range sessions {
		if time.Now().After(expiry) {
			delete(sessions, token)
			deletedCount++
		}
	}
	if deletedCount > 0 {
		log.Printf("Cleaned up %d expired session(s)", deletedCount)
	}
}

func generateSessionToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {

		log.Printf("FATAL: crypto/rand.Read failed: %v. Server cannot generate secure tokens.", err)

	}
	return hex.EncodeToString(bytes)
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowedOrigins := []string{
		"https://0xreyes.github.io",
		"http://localhost:3000",
		"https://localhost:3000",
		"http://localhost:3001",
		"http://localhost:8080",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:3001",
		"http://127.0.0.1:8080",
	}

	for _, allowed := range allowedOrigins {
		if origin == allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func makeCookie(r *http.Request, path string, token string) *http.Cookie {
	// FIX: The session expiry should match the cookie expiry for consistency.
	sessionExpiry := time.Now().Add(24 * time.Hour)

	sessionMutex.Lock()
	sessions[token] = sessionExpiry
	sessionMutex.Unlock()

	origin := r.Header.Get("Origin")
	isLocalhost := strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1")

	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     path,
		HttpOnly: true,
		Secure:   !isLocalhost, // Secure should be true for non-localhost environments
		SameSite: func() http.SameSite {
			if isLocalhost {
				return http.SameSiteLaxMode
			}
			return http.SameSiteNoneMode
		}(),
		Expires: sessionExpiry,
	}
	return cookie
}

// loginHandler handles user login by generating and setting an auth token.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "POST" {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := generateSessionToken()

	// FIX: The cookie path should be "/" to ensure it's sent for all requests
	cookie := makeCookie(r, "/", token)
	http.SetCookie(w, cookie)

	response := AuthResponse{
		Success: true,
		Message: "Authentication successful",
		Token:   token, // Including the token in the body is useful for clients that prefer header-based auth.
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// verifyHandler checks if the current request is authenticated.
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if isAuthenticated(r) {
		response := AuthResponse{Success: true, Message: "Authenticated"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		writeJSONError(w, "Not authenticated", http.StatusUnauthorized)
	}
}

func isAuthenticated(r *http.Request) bool {
	var token string

	if cookie, err := r.Cookie("auth_token"); err == nil {
		token = cookie.Value
	}

	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		return false // No token found.
	}

	sessionMutex.RLock()
	expiry, exists := sessions[token]
	sessionMutex.RUnlock()

	// Check if the session exists and has not expired.
	if exists && time.Now().Before(expiry) {
		log.Printf("Authentication successful for request to %s", r.URL.Path)
		return true
	}

	if !exists {
		log.Printf("Authentication failed: token not found in session store.")
	} else {
		log.Printf("Authentication failed: token has expired.")
	}

	return false
}

func isAllowedTarget(targetURL string) bool {
	allowedSubstrings := []string{"ip-tools"}
	for _, sub := range allowedSubstrings {
		if strings.Contains(targetURL, sub) {
			return true
		}
	}
	return false
}

func corsAnywhereHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !isAuthenticated(r) {
		writeJSONError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// The path contains the target URL, remove the leading "/"
	targetURLStr := r.URL.Path[1:]

	// FIX: Forward query parameters from the original request.
	if r.URL.RawQuery != "" {
		targetURLStr += "?" + r.URL.RawQuery
	}

	if targetURLStr == "" {
		writeJSONError(w, "Missing target URL", http.StatusBadRequest)
		return
	}

	// Prepend scheme if missing.
	if !strings.HasPrefix(targetURLStr, "http://") && !strings.HasPrefix(targetURLStr, "https://") {
		targetURLStr = "https://" + targetURLStr
	}

	parsedURL, err := url.Parse(targetURLStr)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		writeJSONError(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	// Check if the target is in the allowlist.
	if !isAllowedTarget(targetURLStr) {
		log.Printf("Forbidden: Target URL '%s' is not allowed", targetURLStr)
		writeJSONError(w, "Access to this target is forbidden.", http.StatusForbidden)
		return
	}

	// Create a new request to the target URL.
	req, err := http.NewRequest(r.Method, parsedURL.String(), r.Body)
	if err != nil {
		log.Printf("Failed to create request to %s: %v", targetURLStr, err)
		writeJSONError(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Forward essential headers from the original request.
	forwardedHeaders := []string{
		"Content-Type",
		"Accept",
		"User-Agent",
		"Accept-Encoding", // FIX: Added Accept-Encoding to allow for compressed responses.
	}
	for _, key := range forwardedHeaders {
		if value := r.Header.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}

	if strings.Contains(parsedURL.Host, "github.com") {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch target %s: %v", targetURLStr, err)
		writeJSONError(w, "Failed to fetch target URL", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if strings.ToLower(key) == "access-control-allow-origin" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		const maxBodySize = 10 * 1024 * 1024 // 10 MB limit
		_, err = io.Copy(w, io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("Error copying response body: %v", err)
		}
	}
}
