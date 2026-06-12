# Stage 1: build React
FROM docker.io/library/node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build Go binary
FROM docker.io/library/golang:1.25.0-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -o sentinel ./cmd/server/ && \
    mkdir -p /data/sentinel && chown 65532:65532 /data/sentinel

# Stage 3: minimal runtime image
# nonroot user (65532) owns /data/sentinel so the process can write templates.json
FROM gcr.io/distroless/static:nonroot
COPY --from=backend /app/sentinel /sentinel
COPY --from=backend --chown=65532:65532 /data/sentinel /data/sentinel
EXPOSE 8080
ENTRYPOINT ["/sentinel"]
