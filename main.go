package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	http.HandleFunc("/", corsAnywhereHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func corsAnywhereHandler(w http.ResponseWriter, r *http.Request) {
	// Extract target URL from path
	targetURL := r.URL.Path[1:] // Remove leading "/"
	if targetURL == "" {
		http.Error(w, "Missing target URL", http.StatusBadRequest)
		return
	}

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

	// Create new request to target URL
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// List of browser-injected headers to exclude
	excludedHeaders := []string{
		"Cookie",
		"Referer",
		"Origin",
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
	}

	// Copy only non-excluded headers from original request
	for key, values := range r.Header {
		if !contains(excludedHeaders, key) {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// Add GitHub token from environment variable if targeting api.github.com
	if strings.Contains(parsedURL.Host, "api.github.com") {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			http.Error(w, "GitHub token not configured", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "token "+token)
	}

	// Make request to target
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch target", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle OPTIONS preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set response status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response: %v", err)
	}
}

// contains checks if a string is in a slice
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}
