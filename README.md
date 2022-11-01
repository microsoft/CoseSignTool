# CoseParser and CoseSignTool
CoseParser is a library of functions for COSE signing and validation for use by .NET applications. CoseSignTool is a platform-agnostic command line application to COSE sign files and validate COSE signatures.
### Requirements
CoseParser depends on System.Formats.Cbor version 7.0.0-preview.2.22115.7 and System.Security.Cryptography.Cose version 7.0.0-preview.2.22115.7 via NuGet package. Do not attempt to use later versions of either package as this will change the fundamental data structures it depends on.

CoseSignTool depends only on CoseParser and Microsoft.Extensions.Configuration.CommandLine. It uses NuGet package version 7.0.0-preview.7.22375.6 but other versions may be compatible.