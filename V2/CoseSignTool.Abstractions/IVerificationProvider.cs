// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

/// <summary>
/// Interface for plugins that provide verification capabilities.
/// Plugins configure and return validators; the main exe handles I/O and formatting.
/// </summary>
public interface IVerificationProvider
{
    /// <summary>
    /// Gets the name of the verification provider (e.g., "X509", "MST", "SCITT").
    /// Used for display and identification purposes.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets a short description of what this provider verifies.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the priority order for this provider's validators.
    /// Lower numbers run first. Signature validation should be 0, chain validation 10, etc.
    /// </summary>
    int Priority { get; }

    /// <summary>
    /// Adds verification-specific options to the verify command.
    /// Examples: --trust-roots, --subject-name, --mst-endpoint, etc.
    /// </summary>
    /// <param name="command">The verify command to add options to.</param>
    void AddVerificationOptions(Command command);

    /// <summary>
    /// Determines if this provider is activated based on the parsed options.
    /// Called to check if any of this provider's options were specified.
    /// </summary>
    /// <param name="parseResult">The parsed command-line result.</param>
    /// <returns>True if this provider should contribute to verification.</returns>
    bool IsActivated(ParseResult parseResult);

    /// <summary>
    /// Creates validators based on the provided options.
    /// Returns validators to add to the verification pipeline.
    /// </summary>
    /// <param name="parseResult">The parsed command-line result.</param>
    /// <returns>One or more validators to add to the pipeline.</returns>
    IEnumerable<IValidator> CreateValidators(ParseResult parseResult);

    /// <summary>
    /// Gets metadata about the verification result (for display purposes).
    /// Called after verification completes to provide additional context.
    /// </summary>
    /// <param name="parseResult">The parsed command-line result.</param>
    /// <param name="message">The COSE message that was verified.</param>
    /// <param name="validationResult">The validation result.</param>
    /// <returns>Metadata dictionary with provider-specific details.</returns>
    IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult);
}