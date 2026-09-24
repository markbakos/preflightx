# Releasing PreflightX

This runbook describes the work required to publish PreflightX through GitHub Releases and package channels such as the Arch User Repository (AUR), Homebrew, and WinGet. It is a plan, not evidence that a release or store package exists.

## Current status

As of 2026-09-24:

- The public GitHub repository is the upstream source. The latest verified CI run is green for lint and the Ubuntu, macOS, and Windows test jobs at [`ddff2ca`](https://github.com/markbakos/preflightx/actions/runs/36053219549).
- No release tag or GitHub release has been published. The repository has a CI workflow, but no release-build workflow.
- There is no `LICENSE`, Arch `PKGBUILD`/`.SRCINFO`, Homebrew tap/formula, or WinGet manifest. `Cargo.toml` has no license metadata. `publish = false` only disables crates.io publication; it does not block these channels.
- The product identity, publisher name, license, signing setup, and first supported release targets are unresolved.
- The current OS sandbox is Linux-only. macOS and Windows scans fail closed unless the user explicitly opts out with `--no-sandbox`. CI passing on those systems does not add native sandbox protection.

So, **the release pipeline and store listings are not ready to publish yet**. A Linux x86_64 AUR package is the smallest useful first channel after the gates below are addressed.

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

- [ ] Choose the software license and add its license file and Cargo metadata. Do not publish under a guessed license.
- [ ] Choose the publisher/display name and maintainer contact that will appear in package metadata. WinGet also needs a stable `Publisher.Package` identifier.
- [ ] Choose the first release version and supported target list. Linux x86_64 is the only sensible initial AUR target; Arch's AUR rules require x86_64 support.
- [ ] Choose who owns and protects release signing keys, how the public verification keys are distributed, and how keys are revoked or rotated.
- [ ] Choose whether publishing starts with AUR only or waits for macOS/Windows sandbox backends. Do not imply that macOS or Windows scans are OS-sandboxed while their current CLI path requires `--no-sandbox`.

### Release build and supply-chain setup

- [ ] Add a tag-triggered release workflow that builds only from a reviewed, protected version tag with locked dependencies.
- [ ] Build a named archive for every supported OS/architecture and include the `preflightx` executable, license, and concise install/use notes.
- [ ] Generate SHA-256 checksums, a software bill of materials (SBOM), and build provenance for each published binary. Sign the release tag and artifacts.
- [ ] Keep release permissions separate from ordinary CI. Use protected release environments and short-lived OIDC credentials where a publishing service supports them; do not store long-lived publishing credentials on a developer laptop.
- [ ] Add branch protection and required review for release workflow/rule changes. Add `CODEOWNERS` for those files.
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

- [ ] Choose and protect the release tag format, for example `vX.Y.Z`, and keep it in sync with `Cargo.toml`.
- [ ] Build Linux x86_64 from the tag with `cargo build --release --locked`; add other targets only after their builds and runtime claims are validated.
- [ ] Package immutable, versioned assets such as `preflightx-vX.Y.Z-linux-x86_64.tar.gz` and produce `SHA256SUMS`, signatures, SBOM, and provenance.
- [ ] Verify the downloaded archive, signature/provenance, executable permissions, `preflightx --version`, `preflightx doctor`, and a benign synthetic scan in a clean VM.
- [ ] Publish checksums, public verification-key fingerprints, release notes, and a dated validation/transparency report alongside the assets.

### Arch Linux AUR: `preflightx-bin`

The AUR hosts the `PKGBUILD` recipe, not the built binary. Users build/install from that recipe with an AUR helper such as `yay`; the recipe should fetch the upstream PreflightX release asset. AUR packages are community contributions and are not thoroughly vetted, so keep the recipe short and auditable. See the [AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines) and [package creation guide](https://wiki.archlinux.org/title/Creating_packages).

- [ ] Check the current AUR for an existing `preflightx-bin` package before creating one.
- [ ] Select the license and include the corresponding license file in the upstream source/release and the Arch package metadata.
- [ ] Write a minimal `PKGBUILD` for one exact version and x86_64 artifact. It should download only the matching PreflightX release files, verify the SHA-256 checksum and signature against a pinned public-key fingerprint, then install the binary and documentation. It must not fetch or run target repositories, samples, or package-manager scripts from scanned projects.
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

Release testing should build and install **PreflightX itself** in disposable, clean operating-system environments. Smoke tests should scan only benign, synthetic fixtures. Do not download, install, execute, or scan real malicious packages as part of building releases, testing package recipes, validating stores, or updating manifests. The scanner's campaign regressions remain reconstructed inert text and generated bytes; they are not package artifacts.

## What you will need to provide

These choices and account-owned operations cannot be safely guessed or completed from this repository:

1. The license and legal permission to publish the project.
2. The publisher/display name, maintainer contact, and stable WinGet identifier.
3. The first channel and supported target matrix. Recommended first package: Linux x86_64 AUR only after the Linux release artifact and Linux release gates are ready.
4. Ownership of signing keys and any Apple Developer ID account/certificate needed for macOS distribution.
5. AUR account plus a dedicated SSH key, Homebrew tap repository ownership, and the GitHub permissions/reviewers for protected releases.
6. The decision to keep macOS/Windows distribution blocked until native sandbox support exists, or to define a narrower, explicitly documented release policy for those platforms.

No store account, release credential, signing key, or package repository has been created by this work.

## Official references

- [Arch AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines)
- [Homebrew taps](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap)
- [Homebrew formulae](https://docs.brew.sh/Formula-Cookbook)
- [Apple notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [WinGet manifests](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest)
- [WinGet package submission](https://learn.microsoft.com/en-us/windows/package-manager/package/repository)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect)
