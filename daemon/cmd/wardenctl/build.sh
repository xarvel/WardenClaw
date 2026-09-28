#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Cross-build of wardenctl without cgo: dist/wardenctl-<os>-<arch> and SHA256SUMS.
# Run from anywhere: cmd/wardenctl/build.sh [go]   (default: go from PATH or ~/sdk/go/bin/go)
set -eu
cd "$(dirname "$0")"
GO=${1:-$(command -v go || echo "$HOME/sdk/go/bin/go")}
mkdir -p dist
for t in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
	os=${t%/*} arch=${t#*/}
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags "-s -w" -o "dist/wardenctl-$os-$arch" .
	echo "dist/wardenctl-$os-$arch"
done
cd dist && sha256sum wardenctl-* > SHA256SUMS && cat SHA256SUMS
