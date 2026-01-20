// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional interface for verification providers that represent a "root" trust model.
/// Root providers represent a top-level trust model (e.g., X.509, MST receipt trust).
/// </summary>
public interface IVerificationRootProvider : IVerificationProvider
{
    /// <summary>
    /// Gets the stable root identifier (e.g., "x509", "mst").
    /// This is used as the subcommand name under <c>verify</c>.
    /// </summary>
    string RootId { get; }

    /// <summary>
    /// Gets a short display name for the root (e.g. "X509", "MST").
    /// </summary>
    string RootDisplayName { get; }

    /// <summary>
    /// Gets a one-line description for listing available roots.
    /// </summary>
    string RootHelpSummary { get; }
}
