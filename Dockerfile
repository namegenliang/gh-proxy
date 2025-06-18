FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o gh-proxy main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/gh-proxy /app/gh-proxy
COPY public public
COPY config.json .

EXPOSE 8080
ENTRYPOINT ["./gh-proxy"]