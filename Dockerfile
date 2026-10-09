FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /farlink-server ./cmd/farlink-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /farlink-server /farlink-server
VOLUME /var/lib/farlink
# 443/tcp HTTPS+WSS, 80/tcp ACME, 3478/udp STUN/TURN, 5349/tcp TURN over TLS
EXPOSE 443 80 3478/udp 5349
USER root
ENTRYPOINT ["/farlink-server"]
