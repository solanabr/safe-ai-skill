# Releasing safe-ai-skill

A release tag has to point at a commit that already contains the binaries the release ships.
Claude Code installs the plugin from git, and plugin dependency version ranges resolve
`safe-ai-skill--vX.Y.Z` tags. `v1.0.0` broke this: it points at d569b66, and the binaries were
committed afterwards in a8d20f8, so anything that resolves the tag gets a plugin without them.

The order is now build, commit the binaries, tag that commit, publish from it.
`.github/workflows/release.yml` automates every step except the tag, which a maintainer pushes
after reviewing the binary PR.

## One-time repository setup

- **Tag ruleset** for `v*` and `safe-ai-skill--v*`: only maintainers can create them, and nobody
  can update or delete them. A published tag never moves.
- **Immutable releases** turned on, so release assets can't be swapped after publishing.
- **`RELEASE_PAT`** secret (optional): a fine-grained token with contents and pull-requests write.
  Without it the vendor PR is opened with `GITHUB_TOKEN`, which doesn't trigger CI; close and
  reopen the PR to run it.

## Cutting a release

1. **Bump the version** on a branch: `npm/package.json`, `crates/engine/Cargo.toml` and
   `Cargo.lock`, `plugins/safe-ai-skill/.claude-plugin/plugin.json`,
   `.claude-plugin/marketplace.json`, the README badge and the `install.sh` default.
   `sh scripts/check-versions.sh` must pass. Date the CHANGELOG entry. Merge to `main`.
2. **Build.** Actions → Release → Run workflow on `main`, with `version` set to `X.Y.Z` (no `v`).
   The run checks the manifests and that neither tag exists yet, builds the four binaries (Linux:
   static musl, smoke-tested in alpine, debian:11 and ubuntu:20.04; macOS: minimum OS checked),
   attests each binary's build provenance, and opens a PR from `release/vX.Y.Z` that commits them
   with a regenerated `SHA256SUMS`.
3. **Review and merge the PR** once CI is green, using **Create a merge commit**. Squash or rebase
   would give the vendor commit a new SHA.
4. **Tag the vendor commit** (the PR's head) with both names and push them together:

   ```sh
   git fetch origin
   commit=$(git rev-parse origin/release/vX.Y.Z)
   git tag -a vX.Y.Z -m "safe-ai-skill X.Y.Z" "$commit"
   git tag -a safe-ai-skill--vX.Y.Z -m "safe-ai-skill X.Y.Z" "$commit"
   git push --atomic origin vX.Y.Z safe-ai-skill--vX.Y.Z
   ```

   Pushing `vX.Y.Z` runs the publish job. It checks that the manifests say `X.Y.Z`, that
   `safe-ai-skill--vX.Y.Z` points at the same commit, that the binaries match `SHA256SUMS`, and
   that each one carries a provenance attestation from `release.yml`. It then creates the GitHub
   Release from those exact files and runs the npm install e2e against it.
5. **Publish to npm** once the GitHub Release exists, because `postinstall` downloads from it:
   `cd npm && npm publish`.
6. **Downstream:** solana-ai-kit re-pins its `stbr` entry to the tagged commit in its own PR and
   release.

`claude plugin tag --dry-run plugins/safe-ai-skill` (on a clean checkout of the vendor commit)
prints the plugin tag name and checks that `plugin.json` and the marketplace entry agree.

## Tags

| Tag | Used by |
|---|---|
| `vX.Y.Z` | the GitHub Release, which `npm/scripts/postinstall.js` and `install.sh` download from |
| `safe-ai-skill--vX.Y.Z` | Claude Code plugin dependency version ranges |

Both point at the same commit, and that commit contains the binaries.

## 1.0.1 one-off steps

- **Retro-tag 1.0.0.** a8d20f8 is `v1.0.0` plus its vendored binaries and nothing else, and those
  binaries match the release assets. Tag it so version ranges can resolve 1.0.0:

  ```sh
  git tag -a safe-ai-skill--v1.0.0 -m "safe-ai-skill 1.0.0" a8d20f8
  git push origin safe-ai-skill--v1.0.0
  ```

  Leave `v1.0.0` where it is. Moving a published tag breaks every cached checkout and checksum.
- **1.0.1 is the first release built this way.** Follow steps 1–6. The vendor PR replaces all four
  1.0.0 binaries, and the two Linux ones become static.
- **After the 1.0.1 vendor PR merges,** delete the `legacy_1_0_0` hash list from the
  `verify-attestations` job in `.github/workflows/ci.yml`. From then on every committed binary needs
  an attestation.

## Bumping the toolchain

`RUST_TOOLCHAIN` is pinned in `release.yml` and in the `linux-musl` job of `ci.yml`. Change both in
the same PR, so CI builds the musl targets with the new compiler before a release does.
