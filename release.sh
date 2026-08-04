#!/usr/bin/env bash
# Release a new bitw version: bump version.go, verify, commit, and push the
# vX.Y.Z tag. Pushing the tag triggers .github/workflows/release.yml, which
# builds the binaries and creates the GitHub release.
set -euo pipefail

usage() {
    echo "usage: $0 <version>   (e.g. $0 0.1.2)" >&2
    exit 2
}

[ $# -eq 1 ] || usage
NEW_VERSION="$1"

# Version must be plain X.Y.Z (no v prefix).
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: version must be X.Y.Z (got: $NEW_VERSION)" >&2
    exit 2
fi

# Releases are cut from master only.
if [ "$(git branch --show-current)" != "master" ]; then
    echo "error: releases must be cut from master" >&2
    exit 1
fi

# Working tree must be clean.
if [ -n "$(git status --porcelain)" ]; then
    echo "error: working tree is dirty; commit or stash first" >&2
    exit 1
fi

# Tag must not exist yet.
if git rev-parse "v$NEW_VERSION" >/dev/null 2>&1; then
    echo "error: tag v$NEW_VERSION already exists" >&2
    exit 1
fi

# version.go must match the most recent release tag, so releases are
# sequential (v0.1.1 → v0.1.2, never a skipped bump).
CURRENT_VERSION="$(sed -n 's/^var version = "\(.*\)"$/\1/p' version.go)"
LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || echo none)"
if [ "$LAST_TAG" = "none" ]; then
    echo "error: no previous release tag found — tag the first release manually" >&2
    exit 1
fi
if [ "v$CURRENT_VERSION" != "$LAST_TAG" ]; then
    echo "error: version.go says $CURRENT_VERSION but last tag is $LAST_TAG" >&2
    exit 1
fi

# Bump version.go.
sed -i "s/^var version = \".*\"$/var version = \"$NEW_VERSION\"/" version.go
trap 'git checkout version.go 2>/dev/null || true' ERR

# Verify (fail-closed: a gofmt crash must not look like success).
go test ./... >/dev/null
go vet ./... >/dev/null
UNFORMATTED="$(gofmt -l .)"
if [ -n "$UNFORMATTED" ]; then
    echo "error: gofmt needs changes:" >&2
    echo "$UNFORMATTED" >&2
    exit 1
fi

trap - ERR
git add version.go
git commit -m "chore: bump version to $NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "v$NEW_VERSION"
git push origin "v$NEW_VERSION"

echo
echo "Pushed tag v$NEW_VERSION (commit $(git rev-parse --short HEAD))."
echo "GitHub Actions (release.yml) now builds the binaries and creates the"
echo "release: https://github.com/rbelem/bitw/releases"
