FROM golang:1.24 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ch-podauth ./cmd/ch-podauth

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ch-podauth /ch-podauth
USER nonroot:nonroot
ENTRYPOINT ["/ch-podauth"]
