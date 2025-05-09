# Use a slim base image
FROM golang:1.24.1-alpine as builder

# Install required packages **before** switching users
USER root
RUN apk add --no-cache curl

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Set working directory
WORKDIR /app

# Copy necessary files
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY metrics/ ./metrics/
COPY main.go ./

# Build the Go application
RUN go build -o app main.go

# Final runtime image
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/app .

# Run the application
CMD ["./app"]

