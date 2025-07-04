package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func main() {
	http.HandleFunc("/", corsAnywhereHandler)
	log.Println("Starting CORS proxy on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var allowedPaths = []string{
	"/repos/0xReyes/ip-tools/actions/artifacts",
	"/repos/0xReyes/ip-tools/actions/workflows/backend-api-trigger.yml/dispatches",
}

var runArtifactPattern = regexp.MustCompile(`^/repos/0xReyes/ip-tools/actions/runs/[^/]+/artifacts$`)

func isAllowedPath(path string) bool {
	for _, p := range allowedPaths {
		if path == p {
			return true
		}
	}
	return runArtifactPattern.MatchString(path)
}

func corsAnywhereHandler(w http.ResponseWriter, r *http.Request) {
	// Extract target URL from path
	targetURL := r.URL.Path[1:] // Remove leading "/"
	if targetURL == "" {
		http.Error(w, "Missing target URL", http.StatusBadRequest)
		return
	}
	log.Println("targetURL:", targetURL)

	// Prepend https:// if no scheme is provided
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	// Validate and parse target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	// Restrict to api.github.com and specific endpoints
	if parsedURL.Host != "api.github.com" || !isAllowedPath(parsedURL.Path) {
		http.Error(w, "Target URL not allowed", http.StatusForbidden)
		return
	}

	// Validate origin
	origin := r.Header.Get("Origin")
	if origin != "https://0xreyes.github.io" {
		http.Error(w, "Unauthorized origin", http.StatusForbidden)
		return
	}

	// Handle preflight OPTIONS requests
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "https://0xreyes.github.io")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		w.Header().Set("Access-Control-Max-Age", "86400") // Cache preflight for 24 hours
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Create new request to target URL
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("create request to %s failed: %v", targetURL, err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// List of headers to forward from client
	forwardedHeaders := []string{
		"Content-Type",
		"Accept",
	}

	// Copy only allowed headers from original request
	for _, key := range forwardedHeaders {
		if value := r.Header.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}

	// Set Authorization and User-Agent using server credentials
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		http.Error(w, "GITHUB_TOKEN not set", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "CORS-Proxy/1.0")

	// Make request to target
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("make request to %s failed: %v", targetURL, err)
		http.Error(w, "Failed to fetch target: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy all response headers from the target, including CORS headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Override Access-Control-Allow-Origin for consistency
	w.Header().Set("Access-Control-Allow-Origin", "https://0xreyes.github.io")

	// Set Access-Control-Expose-Headers if not already set
	if w.Header().Get("Access-Control-Expose-Headers") == "" {
		w.Header().Set("Access-Control-Expose-Headers", "*")
	}

	// Set response status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if resp.Body != nil && resp.ContentLength != 0 {
		const maxBodySize = 10 * 1024 * 1024 // 10 MB limit
		_, err = io.Copy(w, io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("Error copying response: %v", err)
		}
	}
}
