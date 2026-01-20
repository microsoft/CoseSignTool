// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Certificate-plugin-specific extension point for contributing additional X.509 signing providers.
/// </summary>
/// <remarks>
/// This avoids requiring certificate-related plugins to participate in generic signing-root wiring.
/// The host will bind these providers under the X.509 signing root.
/// </remarks>
public interface ICertificateSigningMaterialProvider
{
    /// <summary>
    /// Gets the stable provider identifier (e.g., "pfx", "akv", "ats").
    /// </summary>
    string ProviderId { get; }

    /// <summary>
    /// Gets a short display name for the provider.
    /// </summary>
    string ProviderDisplayName { get; }

    /// <summary>
    /// Gets a one-line description for listing available providers.
    /// </summary>
    string ProviderHelpSummary { get; }

    /// <summary>
    /// Gets the underlying implementation command name this provider maps to.
    /// This is an implementation detail and should not be surfaced in user-facing help.
    /// </summary>
    string CommandName { get; }

    /// <summary>
    /// Gets the priority for display ordering (lower is shown first).
    /// </summary>
    int Priority { get; }

    /// <summary>
    /// Gets additional aliases for the provider command.
    /// </summary>
    IReadOnlyList<string> Aliases { get; }
}
