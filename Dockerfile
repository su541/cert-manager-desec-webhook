FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o webhook .

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/su541/cert-manager-desec-webhook"

COPY --from=build /workspace/webhook /usr/local/bin/webhook

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/webhook"]
