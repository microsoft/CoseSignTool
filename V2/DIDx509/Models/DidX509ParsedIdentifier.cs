// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents a parsed DID:X509 identifier with its components.
/// </summary>
public sealed class DidX509ParsedIdentifier
{
    /// <summary>
    /// Gets the original DID string.
    /// </summary>
    public string Did { get; }

    /// <summary>
    /// Gets the version number (currently always "0").
    /// </summary>
    public string Version { get; }

    /// <summary>
    /// Gets the CA fingerprint hash algorithm (sha256, sha384, or sha512).
    /// </summary>
    public string HashAlgorithm { get; }

    /// <summary>
    /// Gets the CA certificate fingerprint (base64url-encoded hash).
    /// </summary>
    public string CaFingerprint { get; }

    /// <summary>
    /// Gets the list of policies included in the DID.
    /// </summary>
    public IReadOnlyList<DidX509Policy> Policies { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DidX509ParsedIdentifier"/> class.
    /// </summary>
    public DidX509ParsedIdentifier(
        string did,
        string version,
        string hashAlgorithm,
        string caFingerprint,
        IReadOnlyList<DidX509Policy> policies)
    {
        Did = did ?? throw new ArgumentNullException(nameof(did));
        Version = version ?? throw new ArgumentNullException(nameof(version));
        HashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
        CaFingerprint = caFingerprint ?? throw new ArgumentNullException(nameof(caFingerprint));
        Policies = policies ?? throw new ArgumentNullException(nameof(policies));
    }

    /// <summary>
    /// Gets a policy by name.
    /// </summary>
    public DidX509Policy? GetPolicy(string policyName)
    {
        foreach (var policy in Policies)
        {
            if (string.Equals(policy.Name, policyName, StringComparison.OrdinalIgnoreCase))
            {
                return policy;
            }
        }
        return null;
    }

    /// <summary>
    /// Checks if a specific policy exists.
    /// </summary>
    public bool HasPolicy(string policyName)
    {
        return GetPolicy(policyName) != null;
    }
}