# CoseSignTool and the CoseHandler libraries
CoseSignTool is a platform-agnostic command line application to create and validate COSE signatures.

CoseHandler is a .NET library of static functions that mirror the functionality of CoseSignTool. Or to put it more accurately, CoseSignTool is a command line shell for CoseHandler.

CoseSignTool and CoseHandler support three commands/methods:
1. Sign: Creates a COSE signature for a file or stream. This signature is saved in a separate file from the source payload, but you may optionally include a copy of the source payload in the signature file.
2. Validate: Validates that a COSE signature is properly formed, has a valid certificate chain, and matches the source payload or its hash.
3. Get: Reads the source payload from a COSE signature and returns the original text, or writes it to file or console.

The CoseSign1, CoseSign1.Abstractions, and CoseSign1.Certicates libraries provide the underlying functionality for CoseSignTool and CoseHandler, and can be called directly for [more advanced scenarios.](./docs/Advanced.md)

## What is COSE?
'COSE' refers to [CBOR Object Signing and Encryption](https://www.iana.org/assignments/cose/cose.xhtml), which is the de-facto standard for signing [Software Bills of Materials (SBOM)](https://www.cisa.gov/sbom). It is also used to provide secure authentication for web and Internet Of Things(IOT) application, and is suitable for signing scripts and other text content. CBOR refers to the [Concise Binary Object Representation](https://datatracker.ietf.org/wg/cbor/about/) Internet standard.

## Why would I use this?
[The US Executive Order on Improving the Nation’s Cybersecurity of May 12, 2021](https://en.wikipedia.org/wiki/Software_supply_chain) requires an SBOM for any software or firmare product in use by the US government. This also includes the libraries and tools those products are built with. Even in consumer software, an SBOM helps you protect your customers from supply chain attacks by enabling you to quickly check the version numbers of all the products in your software supply chain.
CoseSignTool, CoseHandler, and the CoseSign1 libraries are the Microsoft solution for signing SBOMs and, we believe, the most powerful and convenient solution currently on the market.

## How do I get started?
First, download the latest release from GitHub. There will be a fully signed version on NuGet.org soon, but this is [just a pre-release](#state-of-the-project), so there's only the open source version available for now.

If you have the option of calling it from a .NET application, go to [CoseHandler.md](./docs/CoseHandler.md)

Otherwise, go to [CoseSignTool.md](./docs/CoseSignTool.md)

## How do I make this better?
You would like to help? Great!
First [check to make sure the work isn't already planned](#state-of-the-project), then...
* If you find a bug or have a feature reccomendation, [log an issue.](https://github.com/microsoft/CoseSignTool/issues)
* If you would like to contribute actual code to the repo or comment on the pull requests of others, read our [contributor guidelines](./docs/CONTRIBUTING.md) and [style guidelines](./docs/STYLE.md), and then make your contribution.

## State of the project
This is an alpha release, so there are some planned features that are not yet in the product, and you may encounter some bugs. If you do, please [report them here.](https://github.com/microsoft/CoseSignTool/issues)

The planned work is currently tracked only in an internal Microsoft ADO instance but will be moved to Github Issues soon. In the meantime, here is some of the work currently planned.

#### New features
* Investigate adding suport for RFC3161 timestamp counter signatures
* Enable specifying a mandatory cert chain root for validation
* Simplify digest signing scenario
* Support batch operations in CoseSignTool to reduce file and cert store reads
* Publish single file version of CoseSignTool

#### Security, performance, and reliability improvements
* Cache certificate store reads for faster performance
* Ensure type safety on cert store and file reads
* Investigate specific compilation by platform for possible performance gains
* Expand code coverage in unit and integration tests

#### Other
* Move work item tracking to public Github repo
* Re-organize the CoseSignTool unit tests for better readability

## Requirements
CoseSignTool runs on .NET 7. It depends on the libraries from this package and [Microsoft.Extensions.Configuration.CommandLine](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.CommandLine) from NuGet package version 7.0.0.

The libraries depend on [System.Formats.Cbor](https://www.nuget.org/packages/System.Formats.Cbor/) version 7.0.0, [System.Security.Cryptography.Cose](https://www.nuget.org/packages/System.Security.Cryptography.Cose) version 7.0.0, and [System.Runtime.Caching](https://www.nuget.org/packages/System.Runtime.Caching) version 7.0.0 via NuGet package. Do not attempt to use later versions of System.Formats.Cbor or System.Security.Cryptography.Cose, as this breaks some of the fundamental data structures the libraries depend on.

The underlying libraries run on .NET Standard 2.1 but will shortly be released on 2.0 for compatibility with legacy .NET Framework environments. CoseHandler currently builds on .NET 7 but will be switched to .NET Standard 2.0 soon to match the other libraries.

### Trademarks
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft’s Trademark & Brand Guidelines.](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general) Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
