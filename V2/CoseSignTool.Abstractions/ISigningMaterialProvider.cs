// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional interface for plugins that describe a signing material provider.
/// Material providers extend a signing root by providing concrete signing material.
/// Examples: PFX, certificate store, AKV certificate, ATS.
/// </summary>
public interface ISigningMaterialProvider
{
    /// <summary>
    /// Gets the stable provider identifier (e.g., "pfx", "cert-store", "akv-cert", "akv-key").
    /// </summary>
    string ProviderId { get; }

    /// <summary>
    /// Gets the stable root identifier this provider extends (e.g., "x509", "akv").
    /// </summary>
    string RootId { get; }

    /// <summary>
    /// Gets a short display name for the provider.
    /// </summary>
    string ProviderDisplayName { get; }

    /// <summary>
    /// Gets a one-line description for listing available providers.
    /// </summary>
    string ProviderHelpSummary { get; }

    /// <summary>
    /// Gets the underlying implementation command name this material provider maps to.
    /// This is an implementation detail and should not be surfaced in user-facing help.
    /// </summary>
    string CommandName { get; }

    /// <summary>
    /// Gets the priority for display ordering (lower is shown first).
    /// </summary>
    int Priority { get; }
}
