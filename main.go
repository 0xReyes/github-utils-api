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
	log.Println("Starting CORS proxy on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func corsAnywhereHandler(w http.ResponseWriter, r *http.Request) {
	// Always set Access-Control-Allow-Origin to allow all origins
	// This should be set before any potential error responses to ensure CORS headers are present.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*") // Also expose all headers as needed

	// Handle preflight OPTIONS requests
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusNoContent) // 204 No Content
		return
	}

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

	// Create new request to target URL
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("create request to %s failed: %v", targetURL, err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// List of headers to forward
	forwardedHeaders := []string{
		"Content-Type",
		"Authorization",
		"Accept",
		"User-Agent",
	}

	// Copy only allowed headers from original request
	for _, key := range forwardedHeaders {
		if value := r.Header.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}

	// Add GitHub token from environment variable if targeting api.github.com
	if strings.Contains(parsedURL.Host, "api.github.com") {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	// Make request to target
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("make request to %s failed: %v", targetURL, err)
		http.Error(w, "Failed to fetch target: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers from the target to the client's response
	for key, values := range resp.Header {
		// Skip setting Access-Control-Allow-Origin again if it was already set,
		// though our current approach sets it upfront.
		// This check is mainly for robustness if the upstream itself returns CORS headers.
		if strings.ToLower(key) == "access-control-allow-origin" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set response status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body only if body is non-nil and Content-Length is not zero
	if resp.Body != nil && resp.ContentLength != 0 {
		const maxBodySize = 10 * 1024 * 1024 // 10 MB limit
		_, err = io.Copy(w, io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("Error copying response: %v", err)
		}
	}
}
