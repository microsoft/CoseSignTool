---
CoseSignTool
---

# Contributing
*Welcome and thank you for your interest in contributing to the CoseSignTool project!*

## Issues and Feature Requests
Work items are tracked in [Issues](https://github.com/microsoft/CoseSignTool/issues). 

## Style Guidelines
Please respect the current style in the code.
See [Stye.md](./STYLE.md) for details.

## Testing
All unit tests in the repo must pass in Windows, Linux, and MacOS environments to ensure compatitility.

### C#/.NET Tests
Run locally with:
```
dotnet build CoseSignTool.sln
dotnet test CoseSignTool.sln
```

### Native (Rust/C/C++) Tests
Run locally from the `native/rust/` directory:
```
cargo test --workspace --exclude cose-openssl
```
OpenSSL must be installed and `OPENSSL_DIR` set (see `native/rust/.cargo/config.toml`).

## CI/CD Pipeline
The repository uses GitHub Actions with **path-based filtering** to run only the relevant jobs for each change. This saves significant CI time — a C#-only change won't trigger 30+ minutes of Rust/C++ builds, and vice versa.

### Path Filtering Matrix

| Trigger | C# Build & Test | Native Rust/C/C++ | CodeQL (C#) | CodeQL (Rust/C++) | Changelog | Pre-release |
|---------|-----------------|-------------------|-------------|-------------------|-----------|-------------|
| **PR — C# paths changed** | ✅ 4 platforms | ❌ skipped | ✅ | ❌ skipped | ❌ | ❌ |
| **PR — native/ changed** | ❌ skipped | ✅ Rust + C/C++ | ❌ skipped | ✅ | ❌ | ❌ |
| **PR — both changed** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Push to main — C# paths** | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| **Push to main — native/ only** | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Manual release** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (assets) |
| **Weekly schedule** | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |

### What Triggers What

**C# paths** (triggers .NET build, C# CodeQL, and releases):
- `**/*.cs`, `**/*.csproj`, `**/*.sln`
- `*.props`, `*.targets` (CPM/MSBuild changes)
- `Directory.Build.props`, `Directory.Packages.props`
- `Nuget.config`, `global.json`
- `.github/workflows/dotnet.yml`

**Native paths** (triggers Rust build/test/coverage, C/C++ build/test/coverage, Rust/C++ CodeQL):
- `native/**`

### Notes for Contributors
- Native Rust/C/C++ jobs only run on PRs, not on push-to-main (no Rust crate publishing yet).
- Pre-releases are only created when C# code changes are pushed to main.
- The changelog is updated on every push to main regardless of which paths changed.
- CodeQL runs on a weekly schedule for all languages to catch newly discovered vulnerabilities.

## Pull Request Process
_Note: There was a bug in the pull request process which caused Github to lose track of running workflows when the CreateChangelog job completes. The work around is to close and re-open the pull request on the pull request page <span>(https<nolink>://github.com/microsoft/CoseSignTool/pull/[pull-request-number])</span> We beleive this is fixed as of version 1.1.1-pre1 so please log an issue if it reappears._
1. Clone the [repo](https://github.com/microsoft/CoseSignTool).
1. Create a user or feature branch off of main. Do not use the keyword "hotfix" or "develope" in your branch names as these will trigger incorrect release behavior.
1. Make your changes, including adding or updating unit tests to ensure your changes work as intended.
1. Make sure the solution still builds and all unit tests still pass locally.
1. Update any documentation, user and contributor, that is impacted by your changes:
   - [CoseSignTool.md](./CoseSignTool.md) for the CoseSignTool CLI
   - [CoseHandler.md](./CoseHandler.md) for the high-level CoseHandler API
   - [CoseSign1.Headers.md](./CoseSign1.Headers.md) for CWT Claims and header extenders
   - [CWT-Claims.md](./CWT-Claims.md) for SCITT compliance features
   - [Advanced.md](./Advanced.md) for advanced scenarios, async APIs, and low-level usage
   - [CoseSign1.md](../CoseSign1.md) for factory and builder patterns
   - [Plugins.md](./Plugins.md) for plugin development
   - [CertificateProviders.md](./CertificateProviders.md) for certificate provider plugins
1. Push your changes to origin and create a pull request into main from your branch. The pull request automation will re-run the unit tests in Windows, MacOS, and Linux environments.
1. Fix any build or test failures or CodeQL warnings caught by the pull request automation and push the fixes to your branch.
1. Address any code review comments.
1. You may merge the pull request in once you have the sign-off of at least two Microsoft full-time employees, including at least one other developer.
Do not modify CHANGELOG.md, as it is auto-generated.

## Releases
Pre-releases are created automatically when C#/.NET code changes are pushed to main. Native-only changes (Rust/C/C++) update the changelog but do not create pre-releases, as Rust crate publishing is not yet implemented.

Official releases are created manually by the repo owners and do not use the pre-release flag.
In both cases, the built binaries and other assets for the release are made available in .zip files.

### Creating a Manual Release (repo owners)
1. From the [Releases page](https://github.com/microsoft/CoseSignTool/releases), click _Draft a new release_
1. Click _Choose a tag_ and create a new, semantically versioned tag in the format v[Major.Minor.Patch], such as v0.3.2. In general, a Patch release represents a new feature or a group of important bug fixes. A Minor release represents a coherent set of features, and a Major release is either a significant overhaul of the product or a stabilization point in the code after a significant number of Minor releases.
1. Set _Release title_ to "Release _tag_"
1. Click _Generate release notes_
1. Edit the generated release notes to include a brief summary at the top, in user focused language, of what features were added and any important bugs that were fixed.
1. Make sure the _Set as a pre-release_ box is _not_ checked.
1. Click _Publish release_.

## License Information
[MIT License](https://github.com/microsoft/CoseSignTool/blob/main/LICENSE)