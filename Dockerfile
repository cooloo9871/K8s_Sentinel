# Stage 1: build React
FROM docker.io/library/node:20-alpine AS frontend
# Stamped into the UI. Defaults to "dev" so a build without it says so rather
# than claiming a version it is not.
ARG VERSION=dev
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN VITE_APP_VERSION=$VERSION npm run build

# Stage 2: build Go binary
FROM docker.io/library/golang:1.26-alpine AS backend
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
# Links the published package to its source repository on GHCR
LABEL org.opencontainers.image.source="https://github.com/cooloo9871/K8s_Sentinel"
LABEL org.opencontainers.image.description="Kubernetes security management console — Tetragon runtime monitoring and ValidatingAdmissionPolicy control"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=backend /etc/passwd /etc/passwd
COPY --from=backend /etc/group /etc/group
COPY --from=backend /app/sentinel /sentinel
COPY --from=backend --chown=10001:10001 /data/sentinel /data/sentinel
USER sentinel
EXPOSE 8080
ENTRYPOINT ["/sentinel"]
