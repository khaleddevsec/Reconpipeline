# Build stage
FROM golang:alpine AS builder
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo v2.5.0)" \
    -o /threatlens \
    ./cmd/threatlens

# Runtime stage
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /threatlens /threatlens
COPY --from=builder /src/knowledge /knowledge
ENTRYPOINT ["/threatlens"]
CMD ["--help"]
