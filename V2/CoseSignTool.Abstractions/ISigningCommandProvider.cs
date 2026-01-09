// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using System.CommandLine;
using CoseSign1.Abstractions;

/// <summary>
/// Interface for plugins that provide signing commands.
/// Plugins configure and return signing services; the main exe handles all I/O, factories, and formatting.
/// </summary>
public interface ISigningCommandProvider
{
    /// <summary>
    /// Gets the name of the signing command (e.g., "sign-pfx", "sign-azure").
    /// </summary>
    string CommandName { get; }

    /// <summary>
    /// Gets the description of the signing command for help text.
    /// </summary>
    string CommandDescription { get; }

    /// <summary>
    /// Adds command-specific options to the command.
    /// Examples: --pfx, --thumbprint, --ats-endpoint, etc.
    /// Do NOT add --output or payload argument - these are managed by the main exe.
    /// </summary>
    /// <param name="command">The command to add options to.</param>
    void AddCommandOptions(Command command);

    /// <summary>
    /// Creates a configured signing service from parsed command-line options.
    /// The main exe will use this service with DirectSignatureFactory/IndirectSignatureFactory.
    /// </summary>
    /// <param name="options">Parsed command-line options dictionary.</param>
    /// <returns>A configured signing service ready to use.</returns>
    Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options);

    /// <summary>
    /// Gets metadata about the signing operation result (for display purposes).
    /// Called after signing completes successfully.
    /// </summary>
    /// <returns>Metadata dictionary with keys like "Certificate Subject", "Thumbprint", etc.</returns>
    IDictionary<string, string> GetSigningMetadata();

    /// <summary>
    /// Gets an example usage string showing the required options for this provider.
    /// Used in help text and pipeline examples.
    /// </summary>
    /// <example>"--pfx cert.pfx" or "--thumbprint ABC123"</example>
    string ExampleUsage { get; }
}