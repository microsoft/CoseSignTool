# CoseSignTool and CoseParser
CoseSignTool is a platform-agnostic command line application to COSE sign files and validate COSE signatures.

CoseParser is a library of functions for COSE signing and validation for use by .NET applications. 

### Requirements
CoseSignTool depends only on CoseParser and Microsoft.Extensions.Configuration.CommandLine. It uses NuGet package version 7.0.0-preview.7.22375.6 but other versions may be compatible. See [CoseSignTool.md](https://github.com/microsoft/CoseSignTool/blob/main/CoseSignTool.md) for more details.

CoseParser depends on [System.Formats.Cbor](https://www.nuget.org/packages/System.Formats.Cbor/) version 7.0.0-preview.2.22115.7 and [System.Security.Cryptography.Cose](https://www.nuget.org/packages/System.Security.Cryptography.Cose/7.0.0-rc.2.22472.3) version 7.0.0-preview.2.22115.7 via NuGet package. Do not attempt to use later versions of either package as this will change the fundamental data structures it depends on. See [CoseParser.md](https://github.com/microsoft/CoseSignTool/blob/main/CoseParser.md) for more details.