# Releasing dsip-rs

dsip-rs uses siphon-rs's release model (siphon-rs `RELEASING.md`), so a consumer of both sees one convention. The
first release was `v2026.10.29`.

## The two-layer versioning model

1. **Release tags are CalVer** (`v2026.11.02`). A tag names a snapshot of the whole repository. An aggregate of many
   crates cannot make one honest compatibility promise, so the tag does not try; it is a pinnable, changelog-aligned
   name for a commit.
2. **Crate versions are SemVer** (`dsip-session = 0.2.0`). Compatibility lives at the crate level, in each crate's
   `Cargo.toml`.

Do not copy the date into crate versions, and do not invent a workspace-wide SemVer number.

**A third fact is recorded with each release: the DSIP spec it conforms to.** That is the DSIP tag the `spec/` submodule is
pinned to (`git -C spec describe --tags`, for example `poc-v1.0`), and the release notes say it. Moving the
submodule is at least a minor bump of every crate whose behaviour the move changed.

## Tags

- One annotated tag per release: `vYYYY.MM.DD`, matching the changelog heading. A second release on the same day gets
  `.1`, `.2`, …
- Tags are immutable. A bad release is followed by a new one.
- The tag message lists every crate's version and the DSIP spec tag.

## Crate version bumps

All crates are pre-1.0, so the minor digit is the compatibility boundary:

| Change since the crate's last bump | Bump |
|---|---|
| Breaking API change (signature, return type, removed or renamed item) | minor |
| New public API, additive | minor |
| A submodule move that changes the crate's behaviour | minor |
| Fixes only | patch |
| fmt, clippy chores, test-only edits | none |

A return-type change counts as breaking even when existing callers compile. Inter-crate dependencies are `path`
only, so a bump never edits dependents' manifests.

## Changelog

`CHANGELOG.md` follows Keep a Changelog. Work accumulates under `## [Unreleased]`. A release turns it into
`## [YYYY-MM-DD] — workspace release`, which includes:
1. every crate's version, unchanged ones included;
2. the DSIP spec tag;
3. a **Breaking changes** paragraph naming each break and its PR;
4. the entries.

## Checklist

1. Audit each crate since its last bump and classify it by the table above.
2. Bump the `version` lines.
3. Turn `[Unreleased]` into the dated section.
4. Verify: CI green on the release commit — `cargo test --workspace`, `cargo run -p dsip-cli -- vectors run` with
   zero failures, clippy and docs clean on the pinned toolchain, the demos, the wasm build and the web tests.
5. Open a PR and merge it.
6. Tag the merge commit:
   `git tag -a vYYYY.MM.DD -m "workspace release YYYY-MM-DD (DSIP <spec tag>)

   <crate versions>" <sha>`, then push the tag.
7. The tag runs the release workflow (`.github/workflows/release.yml`, about 45 minutes). It refuses a tag that is
   not annotated, a tag without its changelog section, and a `spec/` that is not exactly on a DSIP tag. It then:
   - builds every service's packages and the browser client, and runs the packaging tests CI runs
     (`crates/dsip-node/packaging/test.sh`, `packaging/test.sh`, `crates/dsip-push/packaging/test.sh`,
     `packaging/one-host/test.sh`);
   - creates the GitHub release, its notes from `packaging/release-assets.sh`: the section's opening (spec tag,
     versions, breaking changes), the packages and images, how to verify them, the pinning snippet;
   - attaches each service's static-binary tarballs and `.deb`s for amd64 and arm64, `dsip-web-<v>.tar.gz`,
     `dsip-one-host-<release>.tar.gz` (`configure`, the compose directory pinned to this release's images, the guide)
     and one `SHA256SUMS`, each with a build-provenance attestation;
   - pushes `ghcr.io/feryx-io/dsip-relay`, `dsip-mailbox`, `dsip-push` and `dsip-node` for linux/amd64 and linux/arm64, tagged
     `YYYY.MM.DD` and `latest`, signs each with cosign (keyless, the workflow's identity) and attests it.

   A release made by hand before the tag's run keeps its notes, and the files are added to it. A pull request that
   changes the workflow or `packaging/release-assets.sh`, or a manual run (Actions → release → Run workflow), is a dry
   run: everything but publishing, the files kept as the run's artifact.
8. The first time an image is pushed, GitHub creates its package as private: make each of them public
   (github.com/orgs/feryx-io/packages → the package → Package settings → Change visibility).

## Verifying a release

```sh
sha256sum -c SHA256SUMS
gh attestation verify dsip-relay_0.2.0-1_amd64.deb --repo feryx-io/dsip-rs
cosign verify ghcr.io/feryx-io/dsip-relay:2026.10.31 \
  --certificate-identity-regexp '^https://github.com/feryx-io/dsip-rs/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Downstream

Consumers use git dependencies pinned to a tag, and pin every `dsip-*` crate to the same tag, once, in
`[workspace.dependencies]`:

```toml
dsip-session = { git = "https://github.com/feryx-io/dsip-rs", tag = "v2026.11.02" }
```

Different refs of one repository are different sources to Cargo, which duplicates shared crates and produces
type-mismatch errors.
