// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using System.CommandLine.Parsing;
using CoseSign1.Validation.Trust;

/// <summary>
/// Optional extension interface for verification providers that can contribute trust-plan fragments and
/// trust packs based on command-line options.
/// </summary>
/// <remarks>
/// This interface is the preferred mechanism for driving trust decisions in the CLI.
/// Providers should contribute a <see cref="TrustPlanPolicy"/> fragment describing any requirements
/// they impose. Trust packs and other services should be registered via
/// <see cref="IVerificationProvider.ConfigureValidation"/>.
/// </remarks>
public interface IVerificationProviderWithTrustPlanPolicy : IVerificationProvider
{
    /// <summary>
    /// Creates an optional trust plan policy fragment based on the parsed options.
    /// The returned policy (if any) will be AND-ed with policies from other active providers.
    /// </summary>
    /// <param name="parseResult">The parsed command-line result.</param>
    /// <param name="context">The verification context.</param>
    /// <returns>The trust plan policy fragment, or <see langword="null"/> if none is provided.</returns>
    TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context);
}
