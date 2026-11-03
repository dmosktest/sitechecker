# syntax=docker/dockerfile:1

ARG GO_VERSION=1.23.8-bookworm

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/sitechecker-api ./cmd/api \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/sitechecker-worker ./cmd/worker

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 1000 --create-home app
WORKDIR /app
COPY --from=build /out/sitechecker-api /app/sitechecker-api
COPY --from=build /out/sitechecker-worker /app/sitechecker-worker
USER 1000:1000
EXPOSE 8080
