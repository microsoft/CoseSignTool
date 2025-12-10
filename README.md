# CoseSignTool and the CoseHandler libraries
CoseSignTool is a platform-agnostic command line application to create and validate COSE signatures.

CoseHandler is a .NET library of static functions that mirror the functionality of CoseSignTool. Or to put it more accurately, CoseSignTool is a command line shell for CoseHandler.

CoseSignTool and CoseHandler support three commands/methods:
1. **Sign**: Creates a COSE signature for a file or stream. This signature is saved in a separate file from the source payload, but you may optionally include a copy of the source payload in the signature file.
2. **Validate**: Validates that a COSE signature is properly formed, has a valid certificate chain, and matches the source payload or its hash.
3. **Get**: Reads the source payload from a COSE signature and returns the original text, or writes it to file or console.

Additionally, CoseSignTool supports:
- **Plugin System**: Extend the tool with custom commands and third-party integrations (Azure Code Transparency Service, indirect signatures, etc.)
- **Certificate Provider Plugins**: Use cloud-based signing services, HSMs, or custom certificate sources
  - Built-in support for **Azure Trusted Signing** (Microsoft's managed signing service)
  - Extensible architecture for custom certificate providers
  - See [CertificateProviders.md](./docs/CertificateProviders.md) for details
- **SCITT Compliance**: Automatic CWT (CBOR Web Token) Claims with DID:x509 identifiers for supply chain transparency
- **Async APIs**: Full async/await support for signing operations with streams and cancellation tokens

For plugin development, see:
- [Plugins.md](./docs/Plugins.md) - Comprehensive plugin documentation
- [PluginQuickStart.md](./docs/PluginQuickStart.md) - Quick start guide  
- [PluginAPI.md](./docs/PluginAPI.md) - Complete API reference
- [AzureCTS.md](./docs/AzureCTS.md) - Azure Code Transparency Service plugin documentation
- [CertificateProviders.md](./docs/CertificateProviders.md) - Certificate provider plugin guide

The **CoseSign1**, **CoseSign1.Abstractions**, **CoseSign1.Certificates**, and **CoseSign1.Headers** libraries provide the underlying functionality for CoseSignTool and CoseHandler, and can be called directly for [more advanced scenarios](./docs/Advanced.md), including:
- Custom header extenders for CWT Claims (SCITT compliance)
- Async signing operations with streams
- Custom certificate chain validation
- Indirect signatures for large payloads

## What is COSE?
'COSE' refers to [CBOR Object Signing and Encryption](https://www.iana.org/assignments/cose/cose.xhtml), which is the de-facto standard for signing [Software Bills of Materials (SBOM)](https://www.cisa.gov/sbom). It is also used to provide secure authentication for web and Internet Of Things(IOT) application, and is suitable for signing scripts and other text content. CBOR refers to the [Concise Binary Object Representation](https://datatracker.ietf.org/wg/cbor/about/) Internet standard.

## SCITT Compliance
CoseSignTool supports **SCITT (Supply Chain Integrity, Transparency, and Trust)** compliance through **CWT (CBOR Web Token) Claims** and **DID:x509 identifiers**. SCITT is an emerging IETF standard for creating transparent, verifiable supply chain signatures.

### Key Features
- **Automatic DID:x509 Generation**: Issuer identifiers are automatically derived from your certificate chain
- **CWT Claims Support**: Include standardized claims (issuer, subject, audience, expiration, etc.) in your signatures
- **Enabled by Default**: SCITT compliance is automatically enabled when signing with certificates (can be disabled with `--enable-scitt false`)
- **Fully Customizable**: Override defaults or add custom claims via CLI or programmatic API
- **Opt-Out Available**: Disable automatic CWT claims when not needed for your use case

### Quick Example
```bash
# Basic SCITT-compliant signature
# Automatically includes: DID:x509 issuer, default subject, timestamps
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose

# Custom SCITT signature with specific subject and expiration
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --cwt-subject "software.release.v1.0" \
  --cwt-claims "4=1735689600"  # exp: Jan 1, 2025

# Disable SCITT compliance (no automatic CWT claims)
CoseSignTool sign -f payload.txt -pfx mycert.pfx -s signature.cose \
  --enable-scitt false

# Using Azure Trusted Signing (cloud-based signing)
CoseSignTool sign -f payload.txt -s signature.cose \
  --cert-provider azure-trusted-signing \
  --ats-endpoint https://contoso.codesigning.azure.net \
  --ats-account-name ContosoAccount \
  --ats-cert-profile-name ContosoProfile
```

For complete documentation, see [SCITTCompliance.md](./docs/SCITTCompliance.md) and [CertificateProviders.md](./docs/CertificateProviders.md)

## Why would I use this?
[The US Executive Order on Improving the Nation’s Cybersecurity of May 12, 2021](https://en.wikipedia.org/wiki/Software_supply_chain) requires an SBOM for any software or firmare product in use by the US government. This also includes the libraries and tools those products are built with. Even in consumer software, an SBOM helps you protect your customers from supply chain attacks by enabling you to quickly check the version numbers of all the products in your software supply chain.
CoseSignTool, CoseHandler, and the CoseSign1 libraries are the Microsoft solution for signing SBOMs and, we believe, the most powerful and convenient solution currently on the market.

## How do I get started?

### Using as an executable CLI
Downloadable versions are available in GitHub [releases](https://github.com/microsoft/CoseSignTool/releases) of this repository. Separate page lists the features and how to use them: [CoseSignTool.md](./docs/CoseSignTool.md).

#### Linux
Download and extract the folder with the compiled binaries, then make `CoseSignTool` available on the `$PATH`.

```bash
# download and uzip the release
mkdir -p ~/cosesigntool
curl -L https://github.com/microsoft/CoseSignTool/releases/latest/download/CoseSignTool-Linux-release.zip -o ~/cosesigntool/release.zip
unzip ~/cosesigntool/release.zip -d ~/cosesigntool
# move the directory to a stable location
mv ~/cosesigntool/release ~/.local/bin/cosesigntool
export PATH="$PATH":~/.local/bin/cosesigntool
# cleanup of files
rm -rf ~/cosesigntool
# run the binary
CoseSignTool

> *** CoseSignTool ***
> A tool for signing, validating, and getting payload from Cose signatures.
```

#### MacOS
Similar to Linux, but choose the appropriate macOS architecture:
- For Intel Macs: Download `CoseSignTool-MacOS-x64-release.zip`
- For Apple Silicon Macs (M1/M2/M3): Download `CoseSignTool-MacOS-arm64-release.zip`

If you're unsure of your Mac's architecture, run `uname -m` in Terminal:
- `x86_64` = Intel Mac (use x64 version)
- `arm64` = Apple Silicon Mac (use arm64 version)

#### Windows
Similar to Linux or MacOS you could use PowerShell to download the release, extract and move it to the desired location and to add it to the Path like shown in the example below:

```ps
PS C:\Users\johndoe> Invoke-WebRequest -Uri https://github.com/microsoft/CoseSignTool/releases/latest/download/CoseSignTool-Windows-release.zip -OutFile C:\Users\johndoe\release.zip
PS C:\Users\johndoe> Expand-Archive C:\Users\johndoe\release.zip -DestinationPath C:\Users\johndoe
PS C:\Users\johndoe> Rename-Item -Path "C:\Users\johndoe\release" -NewName "cosesigntool"
PS C:\Users\johndoe> Move-Item -Path C:\Users\johndoe\cosesigntool -Destination C:\Users\johndoe\AppData\Local\
PS C:\Users\johndoe> $env:Path += ";C:\Users\johndoe\AppData\Local\cosesigntool"
PS C:\Users\johndoe> CoseSignTool

*** CoseSignTool ***
A tool for signing, validating, and getting payload from Cose signatures.
```

### Using in .NET
Download a specific version from [releases](https://github.com/microsoft/CoseSignTool/releases). There will be a fully signed version on NuGet.org soon, but this is [just a pre-release](#state-of-the-project), so there's only the open source version available for now.

**Key Libraries and Documentation:**
- **[CoseHandler.md](./docs/CoseHandler.md)** - High-level API for signing and validation
- **[CoseSign1.Headers.md](./docs/CoseSign1.Headers.md)** - CWT Claims and custom header extenders for SCITT compliance
- **[CoseIndirectSignature.md](./docs/CoseIndirectSignature.md)** - Indirect signatures for large payloads
- **[Advanced.md](./docs/Advanced.md)** - Async APIs, timestamps, and advanced scenarios
- **[CoseSign1.md](./CoseSign1.md)** - Factory and builder pattern APIs

**Quick Start Example:**
```csharp
using CoseSign1;
using CoseSign1.Certificates.Local;
using CoseSign1.Headers;

// Certificate-based signing with automatic SCITT compliance
var cert = new X509Certificate2("cert.pfx", "password");
var signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(cert);

// Automatic CWT claims (issuer from DID:x509, subject="unknown.intent")
byte[] payload = File.ReadAllBytes("payload.bin");
var factory = new CoseSign1MessageFactory();
CoseSign1Message signature = factory.CreateCoseSign1Message(
    payload, signingKeyProvider, embedPayload: false);

// Or customize CWT claims
var cwtExtender = new CWTClaimsHeaderExtender()
    .SetSubject("myapp.v1.0")
    .SetExpirationTime(DateTimeOffset.UtcNow.AddYears(1));

CoseSign1Message customSignature = factory.CreateCoseSign1Message(
    payload, signingKeyProvider, embedPayload: false, 
    headerExtender: cwtExtender);
```

## How do I make this better?
You would like to help? Great!
First [check to make sure the work isn't already planned](#state-of-the-project), then...
* If you find a bug or have a feature recommendation, [log an issue.](https://github.com/microsoft/CoseSignTool/issues)
* If you would like to contribute actual code to the repo or comment on the pull requests of others, read our [contributor guidelines](./docs/CONTRIBUTING.md) and [style guidelines](./docs/STYLE.md), and then make your contribution.

## State of the project
This project is actively maintained and ready for production use. While we continue to add features and improvements, the core functionality is stable and well-tested.

The work tracking has been moved to [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues). Here are some areas of ongoing development:

#### Planned Features
* Enhanced batch operations for improved performance
* Additional certificate provider integrations
* Extended SCITT features and compliance options
* Performance optimizations for large-scale signing operations

#### Ongoing Improvements
* Expanding test coverage across all platforms
* Performance profiling and optimization
* Documentation enhancements
* Community-requested features

## Requirements
CoseSignTool runs on .NET 8. It depends on the libraries from this package and [Microsoft.Extensions.Configuration.CommandLine](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.CommandLine) from NuGet package version 7.0.0.

The API libraries all run on .NET Standard 2.0.

### Trademarks
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft’s Trademark & Brand Guidelines.](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general) Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
