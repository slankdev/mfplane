# DIST
FROM golang:1.19 as dist
ARG GIT_SHA=unknown
ARG GIT_BRANCH=unknown
ARG GIT_TAG=unknown
ARG BUILD_DATE=unknown
WORKDIR /opt
COPY ./ ./
RUN CGO_ENABLED=0 go build -o ./bin/starbedctl -ldflags "\
  -X github.com/slankdev/mfplane/pkg/util.gitSHA=$GIT_SHA \
  -X github.com/slankdev/mfplane/pkg/util.gitBranch=$GIT_BRANCH \
  -X github.com/slankdev/mfplane/pkg/util.gitTag=$GIT_TAG \
  -X github.com/slankdev/mfplane/pkg/util.buildDate=$BUILD_DATE \
  " ./cmd/starbedctl/main.go

# FINAL
FROM busybox
LABEL org.opencontainers.image.source https://github.com/slankdev/mfplane
COPY --from=dist /opt/bin/starbedctl /usr/bin/
