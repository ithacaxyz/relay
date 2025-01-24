#!/usr/bin/env bash
set -eo pipefail

if ! command -v cargo set-version 2>&1 >/dev/null
then
    echo "Please install cargo-edit"
    exit 1
fi

echo "Setting version in Cargo.toml to $1"
cargo set-version $1

echo "Committing and tagging"
git commit -m "chore: release $1"
git tag $1
