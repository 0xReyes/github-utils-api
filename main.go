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
	http.HandleFunc("/", githubProxyHandler)
	log.Println("Starting GitHub API proxy on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func githubProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	requestedPath := r.URL.Path[1:]
	if requestedPath == "" {
		log.Printf("Error: Missing target URL for request from %s", r.RemoteAddr)
		http.Error(w, "Missing target URL", http.StatusBadRequest)
		return
	}
	log.Printf("Requested path: %s", requestedPath)

	targetURL := "https://api.github.com/" + requestedPath
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("Error: Failed to parse constructed target URL '%s' for request from %s: %v", targetURL, r.RemoteAddr, err)
		http.Error(w, "Internal server error: Invalid URL construction", http.StatusInternalServerError)
		return
	}

	const githubAPIDomain = "api.github.com"
	allowedGitHubPaths := []string{
		"/repos/0xReyes/ip-tools/actions/artifacts",
		"/repos/0xReyes/ip-tools/actions/workflows/backend-api-trigger.yml/dispatches",
	}
	githubRunArtifactsPrefix := "/repos/0xReyes/ip-tools/actions/runs/"
	githubRunArtifactsSuffix := "/artifacts"

	// Ensure the constructed URL's host is indeed the GitHub API domain.
	if parsedURL.Host != githubAPIDomain {
		log.Printf("Forbidden: Request to non-GitHub domain '%s' from %s (constructed URL: %s)", parsedURL.Host, r.RemoteAddr, targetURL)
		http.Error(w, "Proxy is restricted to specific GitHub API endpoints only.", http.StatusForbidden)
		return
	}
	log.Printf("Target host is GitHub API: %s", parsedURL.Host)

	origin := r.Header.Get("Origin")
	if origin != "https://0xreyes.github.io" {
		log.Printf("Unauthorized origin '%s' for GitHub API request from %s", origin, r.RemoteAddr)
		http.Error(w, "Unauthorized origin for GitHub API.", http.StatusForbidden)
		return
	}
	log.Printf("Origin '%s' validated successfully.", origin)

	isAllowedPath := false
	path := parsedURL.Path

	for _, allowedPath := range allowedGitHubPaths {
		if path == allowedPath {
			isAllowedPath = true
			break
		}
	}

	if !isAllowedPath && strings.HasPrefix(path, githubRunArtifactsPrefix) && strings.HasSuffix(path, githubRunArtifactsSuffix) {
		runIDPart := strings.TrimPrefix(path, githubRunArtifactsPrefix)
		runIDPart = strings.TrimSuffix(runIDPart, githubRunArtifactsSuffix)

		if runIDPart != "" && !strings.Contains(runIDPart, "/") {
			isAllowedPath = true
		}
	}

	if !isAllowedPath {
		log.Printf("Unauthorized GitHub API endpoint path '%s' for request from %s", path, r.RemoteAddr)
		http.Error(w, "Unauthorized GitHub API endpoint.", http.StatusForbidden)
		return
	}
	log.Printf("GitHub API endpoint path '%s' validated successfully.", path)

	if r.Method == "OPTIONS" {
		log.Printf("Handling OPTIONS preflight request for %s", r.URL.Path)
		w.Header().Set("Access-Control-Allow-Origin", "https://0xreyes.github.io")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("Error creating request to %s for %s: %v", targetURL, r.RemoteAddr, err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	log.Printf("Created new request to GitHub: %s %s", req.Method, req.URL.String())

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Println("Error: GITHUB_TOKEN environment variable not set. Cannot authenticate with GitHub API.")
		http.Error(w, "Server configuration error: GITHUB_TOKEN missing.", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+githubToken)
	log.Println("GitHub token applied to outgoing request.")

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "0xReyes-ip-tools-proxy")

	if r.Body != nil && r.Header.Get("Content-Type") != "" {
		req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request to GitHub %s for %s: %v", targetURL, r.RemoteAddr, err)
		http.Error(w, "Failed to fetch target: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	log.Printf("Received response from GitHub with status: %d", resp.StatusCode)

	allowedResponseHeaders := map[string]bool{
		"Content-Type":            true,
		"Content-Length":          true,
		"Cache-Control":           true,
		"ETag":                    true,
		"Last-Modified":           true,
		"Vary":                    true,
		"Date":                    true,
		"Server":                  true,
		"X-GitHub-Request-Id":     true,
		"X-RateLimit-Limit":       true,
		"X-RateLimit-Remaining":   true,
		"X-RateLimit-Reset":       true,
		"X-OAuth-Scopes":          true,
		"X-Accepted-OAuth-Scopes": true,
		"Link":                    true,
	}

	for key, values := range resp.Header {
		canonicalKey := http.CanonicalHeaderKey(key)
		if allowedResponseHeaders[canonicalKey] {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	log.Println("Whitelisted response headers copied to client.")

	w.Header().Set("Access-Control-Allow-Origin", "https://0xreyes.github.io")
	log.Printf("Access-Control-Allow-Origin set to %s", "https://0xreyes.github.io")

	w.WriteHeader(resp.StatusCode)
	log.Printf("Response status code set to %d", resp.StatusCode)

	if resp.Body != nil && resp.ContentLength != 0 {
		const maxBodySize = 10 * 1024 * 1024
		_, err = io.Copy(w, io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("Error copying response body for %s: %v", r.URL.Path, err)
		} else {
			log.Printf("Response body copied for %s.", r.URL.Path)
		}
	} else {
		log.Printf("No response body to copy for %s.", r.URL.Path)
	}
}
