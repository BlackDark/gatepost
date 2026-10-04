# Pinned by digest (multi-arch index, verified against the registry): a moving
# `golang:1.26-alpine` tag lets anyone who pushes that tag change the toolchain
# - and therefore the shipped binary - without a commit in this repo.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /repo
COPY . .
WORKDIR /repo/cmd/gatepost-extauthz
RUN --mount=type=cache,target=/go/pkg/mod go mod download
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/amd64/gatepost-extauthz . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /out/arm64/gatepost-extauthz .

# Pinned by digest for the same reason as the builder above: the runtime image
# is part of the auth boundary, so its base must not be movable by a third party.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETARCH
COPY --from=build /out/${TARGETARCH}/gatepost-extauthz /gatepost-extauthz
USER nonroot:nonroot
ENTRYPOINT ["/gatepost-extauthz"]
