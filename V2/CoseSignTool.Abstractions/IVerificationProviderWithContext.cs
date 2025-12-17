// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional extension interface for verification providers that need additional runtime context
/// (e.g., detached payload bytes) to create correct validators.
/// </summary>
public interface IVerificationProviderWithContext : IVerificationProvider
{
    /// <summary>
    /// Creates validators using the parsed command-line result and additional verification context.
    /// </summary>
    IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult, VerificationContext context);
}
