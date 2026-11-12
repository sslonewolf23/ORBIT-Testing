FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/orbit-witness .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build --chown=nonroot:nonroot /out/orbit-witness /orbit-witness
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/orbit-witness"]
