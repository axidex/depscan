# syntax=docker/dockerfile:1

# Pinning --platform=$BUILDPLATFORM keeps the Go compile native (fast); the
# binary is cross-compiled for $TARGETARCH, so no emulation is needed to build.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src

# Download modules in a separate layer so source edits don't bust the cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/craftnovate ./cmd/craftnovate

# ---- runtime stage: minimal Alpine with the tools craftnovate shells out to ----
FROM alpine:3.21

LABEL org.opencontainers.image.source="https://github.com/axidex/craftnovate" \
      org.opencontainers.image.title="craftnovate" \
      org.opencontainers.image.description="Automated dependency-update PRs for Sourcecraft" \
      org.opencontainers.image.licenses="MIT"

# git: the worker pushes branches via `git worktree`/`git push`.
# openssh-client: pushing to an ssh:// remote.
# ca-certificates: public TLS roots. curl: fetch the internal Yandex roots.
RUN apk add --no-cache git openssh-client ca-certificates curl \
    && git config --system --add safe.directory '*' \
    && curl -sSfL https://crls.yandex.net/allCAs.pem >> /etc/ssl/certs/ca-certificates.crt \
    && curl -sSfL https://crls.yandex.net/YandexInternalRootCA.crt >> /etc/ssl/certs/ca-certificates.crt

COPY --from=build /out/craftnovate /usr/local/bin/craftnovate

WORKDIR /repo

# Runs as root on purpose: as a CI cube the script writes a git worktree into the
# mounted checkout's .git (root-owned), so a non-root image fails with "unable to
# create directory for .git/refs/...". safe.directory '*' (above) trusts it. For
# local `docker run --write`, pass `-u "$(id -u):$(id -g)"` to keep file ownership.
#
# No ENTRYPOINT on purpose: the runner executes the cube script via `sh -c …`, so
# an ENTRYPOINT of craftnovate would capture that as arguments ("unknown command
# sh"). craftnovate is on PATH; CMD is just the default for a bare `docker run`.
CMD ["craftnovate"]
