# CORS Anywhere API (Go)

A lightweight Go-based GitHub API

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/cors-anywhere-go.git
   cd cors-anywhere-go
   ```
2. Set the GitHub token:
   ```bash
   export GITHUB_TOKEN=your_token_here
   ```
3. Build and run the server:
   ```bash
   go build
   ./cors-anywhere-go
   ```

The server runs on `http://localhost:8080`.

## Usage
Send requests to the server with the target URL in the path:
```bash
curl -X GET http://localhost:8080/api.github.com/user -H "Content-Type: application/json"
```
This proxies a request to `https://api.github.com/user`, adding the GitHub token and CORS headers.
