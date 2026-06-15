# Stage 1: build React
FROM docker.io/library/node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build Go binary
FROM docker.io/library/golang:1.25-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist
RUN addgroup -S -g 10001 sentinel && \
    adduser -S -u 10001 -G sentinel -H -s /sbin/nologin sentinel && \
    CGO_ENABLED=0 GOOS=linux go build -o sentinel ./cmd/server/ && \
    mkdir -p /data/sentinel && \
    touch /data/sentinel/.keep && \
    chown -R sentinel:sentinel /data/sentinel

# Stage 3: minimal runtime image
FROM scratch
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=backend /etc/passwd /etc/passwd
COPY --from=backend /etc/group /etc/group
COPY --from=backend /app/sentinel /sentinel
COPY --from=backend --chown=10001:10001 /data/sentinel /data/sentinel
USER sentinel
EXPOSE 8080
ENTRYPOINT ["/sentinel"]
