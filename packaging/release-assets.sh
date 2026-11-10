#!/usr/bin/env bash
# Gather a workspace release's service artifacts into dist/release/ (after the packages are built: packaging/build.sh
# dsip-relay dsip-mailbox dsip-push dsip-web and crates/dsip-node/packaging/build.sh), with one SHA256SUMS over all of them and
# the release notes, notes.md: the changelog section's opening (spec tag, crate versions, breaking changes), the
# packages and images, how to verify them, and the pinning snippet.
#   packaging/release-assets.sh <tag>     e.g. v2026.11.02, whose section is "## [2026-11-02]"
#   packaging/release-assets.sh --dry-run the [Unreleased] section, under the tag v0000.00.00-dry-run
# The release workflow (.github/workflows/release.yml) runs it; RELEASING.md describes the release.
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/.."
case ${1:-} in
  --dry-run) TAG=v0000.00.00-dry-run; HEADING='## [Unreleased]' ;;
  v[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]|v[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[0-9]*)
    TAG=$1; d=${TAG#v}; HEADING="## [${d:0:4}-${d:5:2}-${d:8}]" ;;
  *) echo "usage: $0 <vYYYY.MM.DD[.n]> | --dry-run" >&2; exit 2 ;;
esac
VERSION=${TAG#v}   # the images' tag
OWNER=${GITHUB_REPOSITORY_OWNER:-feryx-io}; OWNER=${OWNER,,}
OUT=dist/release; rm -rf "$OUT"; mkdir -p "$OUT"
die() { echo "release-assets: $*" >&2; exit 1; }

# every service's tarballs and .debs, both architectures, and the client
for svc in dsip-relay dsip-mailbox dsip-push dsip-node; do
  n=$(ls crates/$svc/dist/*.tar.gz crates/$svc/dist/*.deb 2>/dev/null | wc -l)
  [ "$n" = 4 ] || die "crates/$svc/dist has $n of its 4 tarballs and .debs (amd64, arm64): build them first"
  cp crates/$svc/dist/*.tar.gz crates/$svc/dist/*.deb "$OUT/"
done
WEB=$(ls web/dist/dsip-web-*.tar.gz 2>/dev/null) || die "no web/dist/dsip-web-*.tar.gz: packaging/build.sh dsip-web"
cp "$WEB" "$OUT/"
# the one-host recipe (docs/one-host.md): configure for the .debs, the compose directory
ONE=dsip-one-host-$VERSION
mkdir -p "$OUT/$ONE"
cp -r packaging/one-host/configure packaging/one-host/compose docs/one-host.md "$OUT/$ONE/"
# its compose runs this release's images
sed -i "s|^# DSIP_VERSION=latest .*|DSIP_VERSION=$VERSION                # this release's images|" "$OUT/$ONE/compose/env.example"
grep -q "^DSIP_VERSION=$VERSION" "$OUT/$ONE/compose/env.example" || die "env.example has no DSIP_VERSION line to pin"
tar -czf "$OUT/$ONE.tar.gz" -C "$OUT" "$ONE"; rm -rf "${OUT:?}/$ONE"
(cd "$OUT" && sha256sum -- *.tar.gz *.deb > SHA256SUMS)

# the notes: the section's text up to its first ### heading
SECTION=$(awk -v h="$HEADING" 'index($0, h) == 1 { on = 1; next } on && /^## / { exit } on && /^### / { exit } on' CHANGELOG.md)
[ -n "$(echo "$SECTION" | tr -d '[:space:]')" ] || [ "$TAG" = v0000.00.00-dry-run ] || die "no \"$HEADING\" section in CHANGELOG.md"
SPEC=$(git -C spec describe --tags 2>/dev/null || echo "see spec/")
{
  echo "$SECTION" | sed -e '/./,$!d'
  echo
  echo "The full list of changes: [CHANGELOG.md](https://github.com/$OWNER/dsip-rs/blob/$TAG/CHANGELOG.md). DSIP spec: \`$SPEC\`."
  echo
  echo "## Service packages"
  echo
  echo "Built and tested together at this tag (packaging/test.sh, crates/dsip-push/packaging/test.sh,"
  echo "packaging/one-host/test.sh). The"
  echo "[one-host guide](https://github.com/$OWNER/dsip-rs/blob/$TAG/docs/one-host.md) runs the relay, the mailbox and"
  echo "the hints node on one name."
  echo
  echo "| | Packages (amd64, arm64) | Image (linux/amd64, linux/arm64) |"
  echo "|---|---|---|"
  for svc in dsip-relay dsip-mailbox dsip-push dsip-node; do
    echo "| $svc | \`$(cd "$OUT" && ls ${svc}_*_amd64.deb)\`, \`$(cd "$OUT" && ls $svc-*-linux-amd64.tar.gz)\` (and arm64) | \`ghcr.io/$OWNER/$svc:$VERSION\` |"
  done
  echo "| browser client | \`$(basename "$WEB")\`, for the relay's \`www\` | |"
  echo "| one host | \`$ONE.tar.gz\`: \`configure\` for the .debs, the compose directory, the guide | |"
  echo
  echo "**Verify** the files with \`sha256sum -c SHA256SUMS\` and their provenance with"
  echo "\`gh attestation verify <file> --repo $OWNER/dsip-rs\`; the images are signed by this repository's release"
  echo "workflow (keyless, Sigstore):"
  echo
  echo '```sh'
  echo "cosign verify ghcr.io/$OWNER/dsip-relay:$VERSION \\"
  echo "  --certificate-identity-regexp '^https://github.com/$OWNER/dsip-rs/.github/workflows/release.yml@refs/tags/' \\"
  echo "  --certificate-oidc-issuer https://token.actions.githubusercontent.com"
  echo '```'
  echo
  echo "## Pinning"
  echo
  echo "Pin every \`dsip-*\` crate to this tag, once, in \`[workspace.dependencies]\`. Different refs of one repository are"
  echo "different sources to Cargo."
  echo
  echo '```toml'
  echo "dsip-phone = { git = \"https://github.com/$OWNER/dsip-rs\", tag = \"$TAG\" }"
  echo "dsip-messenger = { git = \"https://github.com/$OWNER/dsip-rs\", tag = \"$TAG\" }"
  echo '```'
} > "$OUT/notes.md"
echo "dist/release for $TAG: $(ls "$OUT" | grep -vc 'notes.md\|SHA256SUMS') files, SHA256SUMS, notes.md"
