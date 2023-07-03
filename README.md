# CoseSignTool and CoseParser
CoseSignTool is a platform-agnostic command line application to COSE sign files and validate COSE signatures.

CoseHandler is a library of functions for COSE signing and validation for use by .NET applications.

CoseSign1, CoseSign1.Abstractions, and CoseSign1.Certicates provide the underlying functionality for CoseHandler and are available for extensions and other advanced COSE signing and validation scenarios.

### Requirements
CoseSignTool runs on .NET 7. It depends on the above libraries and [Microsoft.Extensions.Configuration.CommandLine](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.CommandLine). It uses NuGet package version 7.0.0 but other versions may be compatible. See [CoseSignTool.md](https://github.com/microsoft/CoseSignTool/blob/main/CoseSignTool.md) for more details.

The libraries depend on [System.Formats.Cbor](https://www.nuget.org/packages/System.Formats.Cbor/) version 7.0.0, [System.Security.Cryptography.Cose](https://www.nuget.org/packages/System.Security.Cryptography.Cose) version 7.0.0, and [System.Runtime.Caching](https://www.nuget.org/packages/System.Runtime.Caching) version 7.0.0 via NuGet package. Do not attempt to use later versions of these packages as it will change the fundamental data structures they depend on. See [CoseParser.md](https://github.com/microsoft/CoseSignTool/blob/main/CoseParser.md) for more details.
