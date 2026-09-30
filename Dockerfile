ARG GO_VERSION=1
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -v -o /run-app ./cmd/server


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /run-app /usr/local/bin/run-app
COPY --from=builder /usr/src/app/web/templates /web/templates
COPY --from=builder /usr/src/app/web/static    /web/static

ENV GIN_MODE=release
WORKDIR /
EXPOSE 8080
CMD ["run-app"]