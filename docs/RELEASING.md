# Releasing safe-ai-skill

A release tag has to point at a commit that already contains the binaries the release ships.
Claude Code installs the plugin from git, and plugin dependency version ranges resolve
`safe-ai-skill--vX.Y.Z` tags. `v1.0.0` broke this: it points at d569b66, and the binaries were
committed afterwards in a8d20f8, so anything that resolves the tag gets a plugin without them.

`main` also has to get new hooks and shim code together with the binaries they call. A 1.0.0
engine answers `allow` to subcommands it doesn't know, so 1.0.1's `hooks.json` on top of 1.0.0
binaries would let every Write/Edit through `gate-tamper`. So a release is built, vendored and
tagged on a protected branch `release/vX.Y.Z`, and `main` receives source and binaries in one
merge of that branch. CI enforces the order: the required `binary-versions` check fails on any
branch whose committed binaries aren't the version in `plugin.json`, so a version bump can't be
merged to `main` before its binaries are vendored.

`.github/workflows/release.yml` builds, attests and vendors; a maintainer reviews the vendor
commit, pushes the tags and merges.

## One-time repository setup

- **Branch ruleset** for `release/v*`: no deletion, no force-push, updates restricted to
  maintainers plus the actor the vendor job pushes as (the `RELEASE_PAT` owner, or the GitHub
  Actions app when there is no `RELEASE_PAT`). release.yml's attestations name the branch, so
  whoever can push to it can get a binary attested.
- **Branch protection on `main`** with the CI checks required, including `Binary versions`
  (all three runners) and `Verify binary provenance`.
- **Tag ruleset** for `v*` and `safe-ai-skill--v*`: only maintainers can create them, and nobody
  can update or delete them. A published tag never moves.
- **Immutable releases** turned on, so release assets can't be swapped after publishing.
- **`RELEASE_PAT`** secret (optional): a fine-grained token with contents write whose owner may
  push to `release/v*`. A push made with `GITHUB_TOKEN` doesn't trigger CI, so without it CI first
  runs on the vendor commit when you open the PR to `main` (step 5).

## Cutting a release

1. **Bump the version** on the hotfix or feature branch: `npm/package.json`,
   `crates/engine/Cargo.toml` and `Cargo.lock`, `plugins/safe-ai-skill/.claude-plugin/plugin.json`,
   `.claude-plugin/marketplace.json`, the README badge and the `install.sh` default.
   `sh scripts/check-versions.sh` must pass. Date the CHANGELOG entry. Don't merge to `main`: CI's
   binary-version check fails until step 3, by design.
2. **Create the release branch** from that branch's head and push it. The `release/v*` ruleset
   protects it from then on.

   ```sh
   git switch -c release/vX.Y.Z <hotfix-branch>
   git push origin release/vX.Y.Z
   ```

3. **Build and vendor.** Actions → Release → Run workflow on `release/vX.Y.Z`, with `version` set
   to `X.Y.Z` (no `v`). Any other ref, including `main`, is rejected: publish and CI only accept
   attestations whose source ref is exactly `refs/heads/release/vX.Y.Z`. The run checks the
   manifests and that neither tag exists yet, builds the five binaries (Linux: static musl,
   smoke-tested in alpine, debian:11 and ubuntu:20.04; macOS: minimum OS checked; Windows:
   `+crt-static`, no dynamic C runtime import, `--version` runs), builds the musl and Windows ones
   a second time from clean and fails unless both builds are byte-identical, then a separate attest
   job signs each binary's build provenance (only that job holds `id-token`/`attestations` write;
   it checks out nothing and runs two actions pinned by commit SHA). The vendor job commits the
   binaries, the shim with their sha256 stamped in (`scripts/stamp-shim.sh`) and a regenerated
   `SHA256SUMS` on top of the commit it built from, pushed to `release/vX.Y.Z`.
   - The push is fast-forward only. If the branch moved during the run, the vendor job fails;
     dispatch again on the new head.
   - If the built binaries are byte-identical to the ones already committed, there is nothing to
     commit: the run says so, and step 4 tags the dispatched commit itself.
4. **Review and tag the vendor commit** (the head of `release/vX.Y.Z`). Check the binary diff,
   that `sh scripts/check-binary-versions.sh` passes on a checkout of it, and that its parent is
   the commit you dispatched. Then tag it with both names and push them together:

   ```sh
   git fetch origin
   commit=$(git rev-parse origin/release/vX.Y.Z)
   git tag -a vX.Y.Z -m "safe-ai-skill X.Y.Z" "$commit"
   git tag -a safe-ai-skill--vX.Y.Z -m "safe-ai-skill X.Y.Z" "$commit"
   git push --atomic origin vX.Y.Z safe-ai-skill--vX.Y.Z
   ```

   Pushing `vX.Y.Z` runs the publish job. It checks that the manifests say `X.Y.Z`, that
   `safe-ai-skill--vX.Y.Z` points at the same commit, that each binary reports `X.Y.Z`, that the
   shim's stamped sha256 constants and `SHA256SUMS` match the binaries, and that each one carries a provenance attestation from
   `release.yml` run on `refs/heads/release/vX.Y.Z`. It then creates the GitHub Release from those
   exact files and runs the npm install e2e against it.
5. **Merge `release/vX.Y.Z` to `main`** in one PR, once CI is green, using **Create a merge
   commit**. Squash or rebase would give the tagged commit a new SHA, so `main` wouldn't contain
   it. This is the first time `main` sees the new version, and it gets the source and the
   binaries together.
6. **Publish to npm** once the GitHub Release exists, because `postinstall` downloads from it:
   `cd npm && npm publish`.
7. **Downstream:** solana-ai-kit re-pins its `stbr` entry to the tagged commit in its own PR and
   release.

`claude plugin tag --dry-run plugins/safe-ai-skill` (on a clean checkout of the vendor commit)
prints the plugin tag name and checks that `plugin.json` and the marketplace entry agree.

## Tags

| Tag | Used by |
|---|---|
| `vX.Y.Z` | the GitHub Release (the binaries, the stamped shim as `safe-ai-skill-shim`, `SHA256SUMS`), which `npm/scripts/postinstall.js` and `install.sh` download from |
| `safe-ai-skill--vX.Y.Z` | Claude Code plugin dependency version ranges |

Both point at the same commit, and that commit contains the binaries.

## Still outstanding from 1.0.x

- **Retro-tag 1.0.0 (not done).** a8d20f8 is `v1.0.0` plus its vendored binaries and nothing
  else, and those binaries match the release assets. `safe-ai-skill--v1.0.0` does not exist, so
  version ranges cannot resolve 1.0.0. Tag it:

  ```sh
  git tag -a safe-ai-skill--v1.0.0 -m "safe-ai-skill 1.0.0" a8d20f8
  git push origin safe-ai-skill--v1.0.0
  ```

  Leave `v1.0.0` where it is. Moving a published tag breaks every cached checkout and checksum.
- **The release branch flow has not been used yet.** As of 2026-10-26 the only tag and GitHub
  Release is `v1.0.0`, there is no `release/v*` branch, and the manifests are at 1.2.0. The first
  release cut this way vendors binaries for every version since 1.0.0 in one commit, so expect
  `binary-versions` and `verify-attestations` to fail on any branch that bumps a manifest before
  that vendor commit exists: that is the guard working, not something to waive.

## Before the next release, check

Observed on 2026-10-26 (re-check; the settings drift):

- `main` has no branch protection (the API answers 404), so the required checks listed under
  one-time setup are not enforced and `binary-versions` can be bypassed by a direct merge.
- There is no tag ruleset. `v*` and `safe-ai-skill--v*` can be created, moved and deleted by
  anyone with write access.
- The only ruleset is `release branches` (`release/v*`: creation, update, deletion and
  non-fast-forward rules, active). It lists two bypass actors with mode `always`: repository
  roles 2 and 5 (maintain and admin). Confirm that is who should be able to push there, because
  release.yml's attestations name the branch.
- No `RELEASE_PAT` is visible at repository level (no repository secrets and no environments).
  An organisation-level secret could not be listed with the available token; if there is none,
  the vendor commit is pushed with `GITHUB_TOKEN` and CI does not run on it until the PR to `main`.
- Immutable releases cannot be read without administration access: check the setting by hand.
- npm-e2e.yml's scheduled run skips while the manifest version has no GitHub Release; it only
  proves the install path again once the release is published.

## Bumping the toolchain

`RUST_TOOLCHAIN` is pinned at the top of both `release.yml` and `ci.yml`. Change both in the same
PR, so CI lints, tests and builds the musl targets with the new compiler before a release does.

## The shim's sha256 pins

The shim (`plugins/safe-ai-skill/bin/safe-ai-skill`) carries a `sha256_<platform>=` constant per
prebuilt and refuses to run a binary that doesn't match it: `gate-bash` and `gate-mcp`
block, the other PreToolUse gates ask, SessionStart reports the firewall TAMPERED. An empty
constant means the release ships no binary for that platform. The vendor job stamps the constants;
CI (`verify-plugin-bin`) and publish run `sh scripts/stamp-shim.sh --check plugins/safe-ai-skill/bin`.

To try a local engine build through the plugin, copy it into `bin/` and stamp it:
`sh scripts/stamp-shim.sh plugins/safe-ai-skill/bin`. Don't commit that.

The shim hashes with `sha256sum`, else `shasum -a 256`, looked up at fixed system paths first
(`/usr/bin/sha256sum`, `/bin/sha256sum`, `/sbin/sha256sum`, `/usr/bin/shasum`), then on `PATH`. With
no tool it can't verify the binary and fails open with a notice, like any other environment failure
(`SAFE_AI_SKILL_STRICT=1` blocks). The `PATH` fallback can be steered by a repo's committed
`.claude/settings.json` `env`, but such a repo can equally fake `uname`; see `SECURITY.md`. The test
harness skips the fixed paths with a `.sha-tools-from-path` file beside its copy of the shim;
writing there needs the same access as rewriting the shim.

After a full match the shim caches the binary's fingerprint (device, inode, size, mtime, ctime) in
`$CLAUDE_PLUGIN_DATA/shim-verified-<platform>` and skips the hash on later calls while the
fingerprint and the stamped constant still match; a re-stamped shim or a replaced binary is a miss
and is hashed again. `SAFE_AI_SKILL_SHIM_CACHE=0` turns it off. The residual is in `SECURITY.md`.

**The shim is the trust anchor.** The pins are only as good as the shim that holds them, and
anything that can write the plugin's `bin/` can rewrite the shim (and its constants) as easily as
the binary. The shim's own integrity rests on the H5 write tripwire, which denies the agent's
writes under `~/.claude/plugins`, and on the user's file permissions. Two residuals are equivalent
to a shim rewrite and are accepted: replacing the binary between the hash and the exec (a TOCTOU
window of a few milliseconds), and editing the shim itself. Both need write access to the
plugin directory, which the pin does not try to defend.

## Not done yet

- **Immutable releases** are a repository setting (see one-time setup). Publish can't check it:
  reading it needs administration access, which `GITHUB_TOKEN` doesn't have.
- **Marketplace `archive` source** instead of vendored binaries: a spike is planned for 1.2.
