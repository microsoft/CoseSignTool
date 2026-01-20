// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Feature flags describing host-level behavior for a verification root.
/// </summary>
[Flags]
public enum VerificationRootFeatures
{
    /// <summary>
    /// No special behavior.
    /// </summary>
    None = 0,

    /// <summary>
    /// Indicates the host should prefer counter-signature / receipt trust when available.
    /// </summary>
    PreferCounterSignatureTrust = 1 << 0,

    /// <summary>
    /// Indicates the host may allow a trusted ToBeSigned attestation to satisfy envelope integrity,
    /// skipping primary signature verification.
    /// </summary>
    AllowToBeSignedAttestationToSkipPrimarySignature = 1 << 1,
}
