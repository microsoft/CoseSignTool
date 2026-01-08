// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Parsing;
using CoseSign1.Validation;

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional extension interface for verification providers that can contribute a <see cref="TrustPolicy"/>
/// based on command-line options.
/// </summary>
public interface IVerificationProviderWithTrustPolicy : IVerificationProvider
{
    /// <summary>
    /// Creates an optional trust policy based on the parsed options.
    /// The returned policy (if any) will be AND-ed with policies from other active providers.
    /// </summary>
    /// <param name="parseResult">The parsed command-line result.</param>
    /// <param name="context">The verification context.</param>
    /// <returns>The trust policy, or <see langword="null"/> if none is provided.</returns>
    TrustPolicy? CreateTrustPolicy(ParseResult parseResult, VerificationContext context);
}
