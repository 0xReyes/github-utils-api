# Dockerfile

# Stage 1: Build the Go application
# Use a specific Go version for reproducible builds
FROM golang:1.22-alpine AS builder

# Install git, which is needed for fetching Go modules
RUN apk add --no-cache git

WORKDIR /app

# Copy go.mod and go.sum files to leverage Docker's layer caching.
# This dependency layer is only rebuilt if these files change.
COPY go.mod go.sum ./

# Download all dependencies. This ensures the pq driver is available.
RUN go mod download

# Copy the rest of your source code into the container.
COPY . .

# Build the application into a static, production-ready binary.
# CGO_ENABLED=0 creates a static binary.
# -ldflags="-w -s" strips debug information, reducing the binary size.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /github-proxy .

# Stage 2: Create the final, minimal production image
FROM alpine:latest

# Add ca-certificates for making HTTPS requests (e.g., to your DB)
# and tzdata for correct timezone handling.
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy the compiled binary from the builder stage.
COPY --from=builder /github-proxy .

# Create a dedicated user and group for the application and switch to it.
# Running as a non-root user is a critical security best practice.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Expose the port the app will run on.
EXPOSE 8080

# Set the command to run the application when the container starts.
CMD ["./github-proxy"]
