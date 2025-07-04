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

	log.Println("Starting GitHub IP-Tools restricted proxy on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func corsAnywhereHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "*") // Also expose all headers as needed

	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusNoContent) // 204 No Content
		return
	}

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

	if !strings.Contains(targetURL, "ip-tools") {
		log.Printf("Forbidden: Target URL '%s' does not contain 'ip-tools'", targetURL)
		http.Error(w, "Access to this target is forbidden. URL must contain 'ip-tools'.", http.StatusForbidden)
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
		"Authorization",
		"Accept",
		"User-Agent",
	}

	for _, key := range forwardedHeaders {
		if value := r.Header.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}

	if strings.Contains(parsedURL.Host, "api.github.com") {
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
