// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional interface for plugins that describe a signing "root" model.
/// A signing root is a top-level trust/signing model (e.g., X.509, AKV key-only).
/// </summary>
public interface ISigningRootProvider
{
    /// <summary>
    /// Gets the stable root identifier (e.g., "x509", "akv").
    /// </summary>
    string RootId { get; }

    /// <summary>
    /// Gets the short display name for the root (e.g., "X509", "AKV").
    /// </summary>
    string RootDisplayName { get; }

    /// <summary>
    /// Gets a one-line description for listing available roots.
    /// </summary>
    string RootHelpSummary { get; }

    /// <summary>
    /// Gets the suggested command-line selector for this root (e.g., "--x509").
    /// This is used for help rendering.
    /// </summary>
    string RootSelector { get; }
}
