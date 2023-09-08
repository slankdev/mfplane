# DIST(1)
FROM golang:1.19 as dist1
ARG TARGETOS
ARG TARGETARCH
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/
COPY cmd/agent/main.go cmd/agent/main.go
COPY api/ api/
COPY pkg/ pkg/
COPY ./internal/ internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
  go build -a -o bin/agent -ldflags "\
  -X github.com/slankdev/mfplane/pkg/util.gitSHA=$GIT_SHA \
  -X github.com/slankdev/mfplane/pkg/util.gitBranch=$GIT_BRANCH \
  -X github.com/slankdev/mfplane/pkg/util.gitTag=$GIT_TAG \
  -X github.com/slankdev/mfplane/pkg/util.buildDate=$BUILD_DATE \
  " cmd/agent/main.go

# DIST(2)
FROM golang:1.19 as dist2
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/
COPY pkg/ pkg/
COPY cmd/mikanectl/main.go cmd/mikanectl/main.go
RUN CGO_ENABLED=0 go build -o ./bin/mikanectl -ldflags "\
  -X github.com/slankdev/mfplane/pkg/util.gitSHA=$GIT_SHA \
  -X github.com/slankdev/mfplane/pkg/util.gitBranch=$GIT_BRANCH \
  -X github.com/slankdev/mfplane/pkg/util.gitTag=$GIT_TAG \
  -X github.com/slankdev/mfplane/pkg/util.buildDate=$BUILD_DATE \
  " ./cmd/mikanectl/main.go

# ROOTFS
FROM ghcr.io/wide-vsix/linux-flow-exporter:branch-main as rootfs
COPY --from=dist1 /workspace/bin/agent /usr/bin/agent
COPY --from=dist2 /workspace/bin/mikanectl /usr/bin/mikanectl
ENTRYPOINT ["/usr/bin/agent"]

# FINAL
FROM scratch
LABEL org.opencontainers.image.source https://github.com/slankdev/mfplane
COPY --from=rootfs / /
