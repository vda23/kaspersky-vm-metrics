#!/usr/bin/env bash
set -euo pipefail

inputs=$1
version=$(cat VERSION)
tag="v$version"
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ $(git log -1 --format=%s) == "Release $tag" ]]
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]]
if existing=$(git rev-parse -q --verify "refs/tags/$tag^{commit}"); then
    [[ $existing == "$GITHUB_SHA" ]] || { echo "Tag $tag already points to $existing" >&2; exit 1; }
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/assets" "$work/download"
archives=()
for arch in amd64 arm64; do
    base="kaspersky-vm-metrics-$version-linux-$arch"
    archive="$base.tar.gz"
    cp "$inputs/linux-$arch/dist/$archive" "$work/assets/"
    [[ $(tar -xzOf "$work/assets/$archive" "$base/VERSION") == "$version" ]]
    archives+=("$archive")
done
(cd "$work/assets" && sha256sum "${archives[@]}" > SHA256SUMS)
cp "docs/releases/$version.md" "$work/notes.md"
printf '\n[Протокол проверки и сборки](%s/%s/actions/runs/%s)\n' \
    "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" >> "$work/notes.md"

if release=$(gh release view "$tag" --json isDraft,targetCommitish); then
    if [[ $(jq -r .isDraft <<< "$release") == false ]]; then
        [[ $(gh api "repos/$GITHUB_REPOSITORY/commits/$tag" --jq .sha) == "$GITHUB_SHA" ]]
        echo "$tag is already published at $GITHUB_SHA"
        exit 0
    fi
    [[ $(jq -r .targetCommitish <<< "$release") == "$GITHUB_SHA" ]]
else
    gh release create "$tag" --draft --target "$GITHUB_SHA" \
        --title "Kaspersky VM Metrics $version" --notes-file "$work/notes.md"
fi

(cd "$work/assets" && gh release upload "$tag" "${archives[@]}" SHA256SUMS --clobber)
gh release download "$tag" --dir "$work/download"
cmp "$work/assets/SHA256SUMS" "$work/download/SHA256SUMS"
(cd "$work/download" && sha256sum --strict --check SHA256SUMS)
gh release edit "$tag" --draft=false --latest
[[ $(gh api "repos/$GITHUB_REPOSITORY/commits/$tag" --jq .sha) == "$GITHUB_SHA" ]]
