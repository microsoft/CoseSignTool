// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using CoseSign1.Abstractions;

/// <summary>
/// Marker interface for all signing key assertions.
/// Each extension package defines its own assertion record types.
/// </summary>
/// <remarks>
/// <para>
/// Assertions are neutral facts about the signing key. They do NOT grant trust.
/// Trust is determined by evaluating assertions against a <see cref="TrustPolicy"/>.
/// Each assertion provides a <see cref="DefaultTrustPolicy"/> that represents
/// secure-by-default evaluation semantics for that assertion type.
/// </para>
/// <para>
/// <strong>Implementers:</strong> Create a sealed record type implementing this interface
/// for each distinct assertion your package provides. Include a companion policy class
/// (e.g., <c>X509ChainTrustPolicy</c>) with a static <c>Default</c> property.
/// </para>
/// </remarks>
public interface ISigningKeyAssertion
{
    /// <summary>
    /// Gets the assertion domain (e.g., "x509", "mst", "akv").
    /// Used for logging, diagnostics, and domain-scoped filtering.
    /// </summary>
    string Domain { get; }

    /// <summary>
    /// Gets a human-readable description of this assertion.
    /// Used in trust decision explanations and diagnostics.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the default trust policy for this assertion type.
    /// This policy represents the secure-by-default evaluation for the assertion.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default policy ensures that consumers who don't craft a custom policy
    /// get secure behavior out of the box. Extension authors MUST provide a policy
    /// that requires the assertion to indicate a positive security outcome.
    /// </para>
    /// <para>
    /// <strong>Implementation Note:</strong> Implementers SHOULD back this property
    /// with a static readonly field to ensure a single policy instance is reused.
    /// Example: <c>public TrustPolicy DefaultTrustPolicy => s_defaultPolicy;</c>
    /// where <c>s_defaultPolicy</c> is a <c>private static readonly</c> field.
    /// </para>
    /// </remarks>
    TrustPolicy DefaultTrustPolicy { get; }

    /// <summary>
    /// Gets the signing key this assertion was extracted from, or null for key-agnostic assertions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The provider that creates the assertion sets this property to indicate which
    /// signing key the assertion is associated with. This enables:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Filtering assertions by key type</description></item>
    /// <item><description>Correlating assertions back to their source key</description></item>
    /// <item><description>Diagnostics and logging showing which key produced which assertions</description></item>
    /// </list>
    /// <para>
    /// Key-agnostic assertions (e.g., MST receipt validation) may set this to null
    /// since they validate message-level data rather than key material.
    /// </para>
    /// </remarks>
    ISigningKey? SigningKey { get; }
}
