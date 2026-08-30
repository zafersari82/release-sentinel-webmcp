FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/gatekeeper ./cmd/gatekeeper
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gatekeeper /gatekeeper
USER nonroot:nonroot
ENTRYPOINT ["/gatekeeper"]
