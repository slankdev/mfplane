# Build the manager binary
FROM golang:1.19 as builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/
COPY cmd/manager/main.go cmd/manager/main.go
COPY api/ api/
COPY pkg/ pkg/
COPY ./internal/controller/ internal/controller/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
  go build -a -o bin/manager cmd/manager/main.go

FROM docker.io/library/ubuntu:22.04 as rootfs
COPY --from=builder /workspace/bin/manager /usr/bin/manager
ENTRYPOINT ["/usr/bin/manager"]

FROM scratch
LABEL org.opencontainers.image.source https://github.com/slankdev/mfplane
COPY --from=rootfs / /
