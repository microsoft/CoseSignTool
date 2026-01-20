// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional interface for verification roots that need to influence host-level verification behavior.
/// </summary>
public interface IVerificationRootFeaturesProvider : IVerificationRootProvider
{
    /// <summary>
    /// Gets feature flags controlling host verification behavior for this root.
    /// </summary>
    VerificationRootFeatures RootFeatures { get; }
}
