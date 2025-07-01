# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o github-proxy .

FROM alpine:latest

RUN apk add --no-cache ca-certificates

RUN apk add --no-cache tzdata

WORKDIR /app

COPY --from=builder /app/github-proxy .

COPY .env.example .

EXPOSE 8080

USER 1001:1001

CMD ["./github-proxy"]