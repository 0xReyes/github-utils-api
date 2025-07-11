package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Simple in-memory session store
var sessions = make(map[string]time.Time)

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

func main() {
	http.HandleFunc("/auth/login", loginHandler)
	http.HandleFunc("/auth/verify", verifyHandler)
	http.HandleFunc("/", corsAnywhereHandler)

	log.Println("Starting authenticated proxy server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Generate secure session token
func generateSessionToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Set CORS headers
func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowedOrigins := []string{
		"https://0x.reyes.github.io",
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

// Simple login - just generates a token
func loginHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate session token
	token := generateSessionToken()

	// Store session (expires in 24 hours)
	sessions[token] = time.Now().Add(24 * time.Hour)

	// Set HTTP-only cookie with different settings for localhost vs production
	origin := r.Header.Get("Origin")
	isLocalhost := strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1")

	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Domain:   "api.github.com",
		Path:     "/",
		HttpOnly: true,
		Secure:   !isLocalhost, // false for localhost, true for production
		SameSite: func() http.SameSite {
			if isLocalhost {
				return http.SameSiteLaxMode
			}
			return http.SameSiteNoneMode
		}(),
		Expires: time.Now().Add(24 * time.Hour),
	}

	cookie2 := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Domain:   "raw.githubusercontent.com",
		Path:     "/",
		HttpOnly: true,
		Secure:   !isLocalhost, // false for localhost, true for production
		SameSite: func() http.SameSite {
			if isLocalhost {
				return http.SameSiteLaxMode
			}
			return http.SameSiteNoneMode
		}(),
		Expires: time.Now().Add(24 * time.Hour),
	}

	cookie3 := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !isLocalhost, // false for localhost, true for production
		SameSite: func() http.SameSite {
			if isLocalhost {
				return http.SameSiteLaxMode
			}
			return http.SameSiteNoneMode
		}(),
		Expires: time.Now().Add(24 * time.Hour),
	}
	http.SetCookie(w, cookie)
	http.SetCookie(w, cookie2)
	http.SetCookie(w, cookie3)

	response := AuthResponse{
		Success: true,
		Message: "Authentication successful",
		Token:   token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Verify authentication
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
		response := AuthResponse{Success: false, Message: "Not authenticated"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
	}
}

// Check if request is authenticated
func isAuthenticated(r *http.Request) bool {
	// Debug: Log all cookies
	log.Printf("Request to %s", r.URL.Path)
	for _, cookie := range r.Cookies() {
		log.Printf("Cookie: %s = %s", cookie.Name, cookie.Value)
	}

	// Check cookie first
	if cookie, err := r.Cookie("auth_token"); err == nil {
		log.Printf("Found auth_token cookie: %s", cookie.Value)
		if expiry, exists := sessions[cookie.Value]; exists && time.Now().Before(expiry) {
			log.Printf("Cookie is valid and not expired")
			return true
		} else {
			log.Printf("Cookie is invalid or expired")
		}
	} else {
		log.Printf("No auth_token cookie found: %v", err)
	}

	// Check Authorization header as fallback
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		log.Printf("Found Authorization header: %s", authHeader)
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if expiry, exists := sessions[token]; exists && time.Now().Before(expiry) {
			log.Printf("Bearer token is valid and not expired")
			return true
		} else {
			log.Printf("Bearer token is invalid or expired")
		}
	} else {
		log.Printf("No Authorization header found")
	}

	log.Printf("Authentication failed for request to %s", r.URL.Path)
	return false
}

// Clean up expired sessions
func cleanupSessions() {
	for token, expiry := range sessions {
		if time.Now().After(expiry) {
			delete(sessions, token)
		}
	}
}

// Modified CORS proxy handler with authentication
func corsAnywhereHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Check authentication for all proxy requests
	if !isAuthenticated(r) {
		response := AuthResponse{Success: false, Message: "Authentication required"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Clean up expired sessions periodically
	go cleanupSessions()

	targetURL := r.URL.Path[1:] // Remove leading "/"
	if targetURL == "" {
		http.Error(w, "Missing target URL", http.StatusBadRequest)
		return
	}
	log.Println("targetURL:", targetURL)

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	// Allow ip-tools URLs or the specific job data repository
	if !strings.Contains(targetURL, "ip-tools") && !strings.Contains(targetURL, "job-data-warehouse") {
		log.Printf("Forbidden: Target URL '%s' is not allowed", targetURL)
		http.Error(w, "Access to this target is forbidden.", http.StatusForbidden)
		return
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("create request to %s failed: %v", targetURL, err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	forwardedHeaders := []string{
		"Content-Type",
		"Accept",
		"User-Agent",
	}

	for _, key := range forwardedHeaders {
		if value := r.Header.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}

	if strings.Contains(parsedURL.Host, "api.github.com") || strings.Contains(parsedURL.Host, "github.com") || strings.Contains(parsedURL.Host, "raw.githubusercontent.com") {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("make request to %s failed: %v", targetURL, err)
		http.Error(w, "Failed to fetch target: "+err.Error(), http.StatusBadGateway)
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

	if resp.Body != nil && resp.ContentLength != 0 {
		const maxBodySize = 10 * 1024 * 1024 // 10 MB limit
		_, err = io.Copy(w, io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("Error copying response: %v", err)
		}
	}
}
