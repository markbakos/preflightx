# Releasing PreflightX

This runbook describes the work required to publish PreflightX through GitHub Releases and package channels such as the Arch User Repository (AUR), Homebrew, and WinGet. It is a plan, not evidence that a release or store package exists.

## Current status

As of 2026-09-24:

- The public GitHub repository is the upstream source. The latest verified CI run is green for lint and the Ubuntu, macOS, and Windows test jobs at [`ddff2ca`](https://github.com/markbakos/preflightx/actions/runs/36053219549).
- The project is now licensed under MIT in `LICENSE` and Cargo metadata. The copyright line currently names the PreflightX contributors collectively.
- There is no release tag, published GitHub release, Arch `PKGBUILD`/`.SRCINFO`, Homebrew tap/formula, or WinGet manifest. `publish = false` only disables crates.io publication; it does not block these channels.
- A draft-only release workflow now exists. It has not run yet and stays disabled until a repository administrator sets `PREFLIGHTX_RELEASE_ENABLED=true` after configuring the release environment and tag protections. When enabled, it waits for lint and all three OS test jobs, builds a Linux x86_64 archive, creates an SPDX SBOM and checksums, verifies the tag signature, attests the archive/SBOM, and opens a GitHub draft release.
- Publisher identity, release/tag signing key ownership, account setup, and external repository protections remain unresolved.
- The current OS sandbox is Linux-only. macOS and Windows scans fail closed unless the user explicitly opts out with `--no-sandbox`. CI passing on those systems does not add native sandbox protection.

So, **the release automation is prepared but not validated by a tagged run, and no store listing is ready to publish**. Linux x86_64 AUR remains the proposed first package after the gates below are addressed.

## Recommended distribution model

Publish one versioned, public GitHub Release as the canonical source for platform artifacts. Package channels should point to immutable assets from that release, with their own platform metadata and checksums. This keeps the build in one place and lets users compare what a package manager installs with the upstream release.

Suggested order:

1. GitHub Releases for Linux x86_64 first.
2. AUR `preflightx-bin`, using the Linux x86_64 release asset.
3. Homebrew after macOS artifacts are signed, notarized, and support limitations are resolved.
4. WinGet after Windows artifacts are ready and the Windows sandbox/release policy is resolved.
5. `.deb`, `.rpm`, Scoop, or other channels when demand justifies maintaining them. Chocolatey is not needed for the first release.

For this command-line product, a Homebrew tap is the intended macOS channel; the Mac App Store is not part of the current plan.

## Gates before the first public release

### Product and publisher decisions

- [x] MIT is selected and present in `LICENSE` and Cargo package metadata. Confirm the desired named copyright holder before the first public release if the collective notice should be more specific.
- [ ] Choose the publisher/display name and maintainer contact that will appear in package metadata. WinGet also needs a stable `Publisher.Package` identifier.
- [ ] Choose the first release version and supported target list. The prepared workflow currently limits artifacts to Linux x86_64; Arch's AUR rules require x86_64 support.
- [ ] Choose who owns and protects release signing keys, how the public verification keys are distributed, and how keys are revoked or rotated.
- [ ] Choose whether publishing starts with AUR only or waits for macOS/Windows sandbox backends. Do not imply that macOS or Windows scans are OS-sandboxed while their current CLI path requires `--no-sandbox`.

### Release build and supply-chain setup

- [x] Add a tag-triggered workflow. It rejects non-version, unsigned, lightweight, or non-`main` tags, runs the lint and Ubuntu/macOS/Windows test gates, and builds only with locked dependencies. The first tag run is still required before relying on it.
- [x] Prepare a named Linux x86_64 archive containing the executable, license, and install/use notes. macOS, Windows, and Linux AArch64 artifacts remain out of this initial workflow.
- [x] Prepare SHA-256 checksums, an SPDX SBOM from the locked Rust dependency graph, GitHub build provenance, and a signed SBOM attestation for the archive. The generated assets and attestations remain unverified until the first tagged run.
- [x] Limit release-only token permissions to the release job and use GitHub's short-lived OIDC-backed attestations. No publishing credential is stored in the repository.
- [x] Add `CODEOWNERS` entries for the release workflow, dependency manifest/lockfile, and detection rules.
- [ ] Require code-owner review and protect `v*` release tags in repository settings.
- [ ] Configure the `release` GitHub environment with required reviewers and a tag rule for `v*`, then set `PREFLIGHTX_RELEASE_ENABLED=true`. Referencing an unconfigured environment does not itself create an approval gate.
- [ ] Publish a release note and transparency summary that state scanner/rule/schema versions, supported platforms, sandbox status, validation performed, limitations, and relevant detection changes.
- [ ] Test each release artifact in a clean environment for its claimed platform. Record the exact results; do not treat compilation or a green CI job as proof of sandbox behavior.

GitHub documents [artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) for signed provenance and SBOM attestations, and [OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect) for short-lived workflow credentials. Attestations provide provenance; they do not certify that the program is safe.

### Scanner readiness and platform claims

- [ ] Complete coverage-guided fuzz campaigns for filesystem/path handling, archives, parsers/graphs, Git objects, and report serialization. Existing deterministic mutation tests are useful smoke checks, not fuzz campaigns.
- [ ] Measure findings and coverage against a broader, versioned benign-project corpus. Track false CRITICAL/HIGH findings, incomplete scans, runtime, and memory.
- [ ] Capture and retain evidence that default scans make no outbound network connections and leave target files unchanged.
- [ ] Validate Linux AArch64 compilation and runtime before advertising that target.
- [ ] Implement and test native macOS/Windows sandbox backends before claiming sandboxed scans on those platforms. Until then, either defer those binaries or state clearly that ordinary scans fail closed and that `--no-sandbox` disables OS isolation.
- [ ] Do not claim that a repository is safe or that a reconstructed fixture proves detection of an entire malware family.

The detailed acceptance criteria and scanner invariants are in the private, Git-ignored project files `context/validation.md` and `context/security.md`; they are available in the maintainer checkout but are not public links.

## Channel checklists

### GitHub Releases

GitHub Releases should be the first publishing surface and canonical artifact source.

- [ ] Protect signed, annotated `vX.Y.Z` tags and require they point to reviewed commits on `main`; keep each version in sync with `Cargo.toml`. The workflow rejects an unsigned tag using GitHub's tag-signature verification result.
- [x] Prepare Linux x86_64 from the tag with `cargo build --release --locked`; add other targets only after their builds and runtime claims are validated.
- [x] Prepare immutable, versioned assets such as `preflightx-vX.Y.Z-linux-x86_64.tar.gz`, `SHA256SUMS`, an SPDX SBOM, and GitHub provenance/SBOM attestations.
- [x] Add checks for executable version, `doctor`, and a benign synthetic scan. A tagged run must still pass these checks before the asset can be trusted.
- [ ] Publish checksums, public verification-key fingerprints, release notes, and a dated validation/transparency report alongside the assets.

After every release gate and the `release` environment are ready, create and push a signed annotated tag on the reviewed `main` commit. For example:

```sh
git switch main
git pull --ff-only
git tag -s vX.Y.Z -m "PreflightX vX.Y.Z"
git push origin vX.Y.Z
```

This starts validation and, if the repository variable is enabled and a reviewer approves the environment, creates a **draft**. Review and publish the draft manually only after checking the actual build results and adding the release-specific transparency details.

After downloading an archive, check `SHA256SUMS` and verify its provenance against the expected repository/workflow with GitHub CLI, for example:

```sh
sha256sum --check SHA256SUMS
gh attestation verify preflightx-vX.Y.Z-linux-x86_64.tar.gz \
  --repo markbakos/preflightx \
  --signer-workflow markbakos/preflightx/.github/workflows/release.yml
```

### Arch Linux AUR: `preflightx-bin`

The AUR hosts the `PKGBUILD` recipe, not the built binary. Users build/install from that recipe with an AUR helper such as `yay`; the recipe should fetch the upstream PreflightX release asset. AUR packages are community contributions and are not thoroughly vetted, so keep the recipe short and auditable. See the [AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines) and [package creation guide](https://wiki.archlinux.org/title/Creating_packages).

- [ ] Check the current AUR for an existing `preflightx-bin` package before creating one.
- [x] Use MIT in package metadata and include the upstream `LICENSE` file in the release archive and Arch package.
- [ ] Write a minimal `PKGBUILD` for one exact version and x86_64 artifact. It should download only the matching PreflightX release files and verify their fixed SHA-256 checksum before installing the binary and documentation. If a detached release signature is added, also verify it against a pinned public key. It must not fetch or run target repositories, samples, or package-manager scripts from scanned projects.
- [ ] Generate and commit `.SRCINFO` with `makepkg --printsrcinfo`; regenerate it whenever package metadata changes.
- [ ] Review the recipe, run Arch package checks, and test install, `preflightx --version`, `doctor`, and uninstall in a clean Arch VM/chroot using a benign synthetic repository.
- [ ] Create an AUR account, register a dedicated SSH key, set the intended maintainer name/contact, then push `PKGBUILD` and `.SRCINFO` to the `preflightx-bin` AUR Git repository. Keep the private SSH/signing keys out of GitHub and the repository.
- [ ] Push the AUR package repository to its required `master` branch.
- [ ] For each release, update `pkgver`/`pkgrel`, checksums/signature metadata, and `.SRCINFO`; review user comments and maintain the package.

The intended install command is:

```sh
yay -S preflightx-bin
```

### Homebrew tap: `brew install <publisher>/tap/preflightx`

Homebrew taps are Git repositories containing formulas. A formula can install the versioned upstream archive and its checksum; see [How to Create and Maintain a Tap](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap) and the [Formula Cookbook](https://docs.brew.sh/Formula-Cookbook).

- [ ] Choose the publisher/tap name and create a public repository named `homebrew-tap` (or the corresponding publisher-owned tap repository).
- [ ] Add a `preflightx` formula with immutable release URLs, SHA-256 values, executable installation into `bin`, and a small `test do` smoke test.
- [ ] Tell users that this is a third-party tap and that they should trust the tap/formula before installing it.
- [ ] Build and verify macOS x86_64 and Apple silicon artifacts if both are advertised.
- [ ] Sign with a Developer ID and notarize macOS release binaries before external distribution. Apple documents the required signing, hardened runtime, timestamp, and notarization flow in [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
- [ ] Test installation, `preflightx --version`, `doctor`, and a benign synthetic scan on clean Intel and Apple silicon Macs before updating the tap.
- [ ] For every release, update the formula version, immutable URLs, and checksums; commit and push the tap update.

### WinGet: `winget install <Publisher.Package>`

WinGet installs from versioned YAML manifests in Microsoft's community repository. A submission is a pull request that is automatically validated and then reviewed; see Microsoft's [manifest guide](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest) and [submission guide](https://learn.microsoft.com/en-us/windows/package-manager/package/repository).

- [ ] Choose a stable publisher name and package identifier. Do not invent a publisher identity in the manifest.
- [ ] Produce a Windows x64 release asset and decide whether a portable archive or a silent installer is the correct install type. Add Windows ARM64 only after its build and runtime support are validated.
- [ ] Create the versioned manifest with the direct upstream release URL, SHA-256, architecture, license, publisher, package name, and accurate installer behavior.
- [ ] Run `winget validate` and install/uninstall the manifest in Windows Sandbox, checking both user and administrator scenarios as applicable.
- [ ] Fork `microsoft/winget-pkgs`, add the manifest under the publisher/application/version path, and open a pull request. Respond to automated validation and moderator feedback.
- [ ] For every release, add the new manifest version and submit the update.

### Later channels

- `.deb` and `.rpm`: add when demand warrants, reusing the same versioned, signed, checksummed Linux artifacts.
- Scoop: consider after the direct Windows release and WinGet package are stable.
- Chocolatey: explicitly deferred for the initial release.
- crates.io: optional future convenience only. It is currently disabled with `publish = false` and is not needed for binary package channels.

## Safe release testing boundary

Release testing should build and install **PreflightX itself** in disposable, clean operating-system environments. The GitHub workflow downloads locked Rust build dependencies and a pinned Syft tool on GitHub-hosted runners; it does not run a package manager against scan targets. Smoke tests should scan only benign, synthetic fixtures. Do not download, install, execute, or scan real malicious packages as part of building releases, testing package recipes, validating stores, or updating manifests. The scanner's campaign regressions remain reconstructed inert text and generated bytes; they are not package artifacts.

## What you will need to provide

These choices and account-owned operations cannot be safely guessed or completed from this repository:

1. Confirm whether the collective copyright line should name a person or organization.
2. The publisher/display name, maintainer contact, and stable WinGet identifier.
3. Confirm the initial channel and supported target matrix. The prepared default is Linux x86_64 first, with AUR after a real tagged artifact and release checks pass.
4. Provide/enable a GitHub-recognized GPG or SSH tag-signing key and choose how to rotate it; GitHub attestations cover artifact provenance but do not sign the Git tag.
5. Configure the `release` environment with required reviewers, protect `v*` tags and require code-owner review, then set the `PREFLIGHTX_RELEASE_ENABLED` repository variable to `true`.
6. An AUR account and dedicated SSH key, Homebrew tap ownership, and any other package-repository accounts. Keep macOS/Windows listings deferred until their native sandbox backends exist, or approve a narrower, accurately disclosed policy for those platforms.

No store account, release credential, signing key, tag, GitHub release, or package repository has been created by this work. The workflow builds PreflightX using its locked Rust dependencies and scans only one generated benign text fixture; it never downloads, installs, executes, or scans a real malicious package.

## Official references

- [Arch AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines)
- [Homebrew taps](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap)
- [Homebrew formulae](https://docs.brew.sh/Formula-Cookbook)
- [Apple notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [WinGet manifests](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest)
- [WinGet package submission](https://learn.microsoft.com/en-us/windows/package-manager/package/repository)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub signed tag verification API](https://docs.github.com/en/rest/git/tags)
- [GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify)
- [GitHub environment protections](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [Anchore SBOM Action](https://github.com/anchore/sbom-action/releases/tag/v0.24.0) and [Syft Rust cataloging](https://oss.anchore.com/docs/capabilities/rust/)
