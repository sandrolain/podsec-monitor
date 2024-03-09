FROM golang:1.22.1-alpine AS builder

RUN apk update && apk add --no-cache git ca-certificates

WORKDIR /app
COPY ./ ./

RUN --mount=type=cache,mode=0755,target=/go/pkg/mod go mod download &&\
  CGO_ENABLED=0 GOOS=linux go build -o /service ./src

FROM ubuntu:noble

RUN mkdir /tools

RUN apt-get update && apt-get install ca-certificates git curl -y
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | bash -s -- -b /tools

ENV PATH="/tools:${PATH}"

COPY --from=builder /service /service
ENTRYPOINT ["/service"]
