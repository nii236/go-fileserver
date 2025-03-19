# syntax=docker/dockerfile:1

## Build

FROM golang:1.23.2-bookworm AS base

WORKDIR /app
ADD . ./
RUN go mod download
RUN rm -rf ./dist
RUN mkdir ./dist
RUN go build -o ./dist/mini ./cmd/main.go

## Deploy

FROM debian:bookworm-slim
WORKDIR /
COPY --from=base /app/dist/mini /mini
COPY ./app.json /app.json
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
ENTRYPOINT ["/mini"]
