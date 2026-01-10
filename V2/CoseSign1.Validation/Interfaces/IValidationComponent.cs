// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;

/// <summary>
/// Base interface for all validation pipeline components.
/// </summary>
/// <remarks>
/// <para>
/// Components are passed to the validator orchestrator as a single list.
/// The orchestrator filters components by their specific interface type
/// and invokes them at the appropriate stage:
/// </para>
/// <list type="number">
/// <item><description><see cref="ISigningKeyResolver"/> - Key material resolution</description></item>
/// <item><description><see cref="ISigningKeyAssertionProvider"/> - Trust assertion extraction</description></item>
/// <item><description>Signature Verification - Performed directly using the resolved signing key</description></item>
/// <item><description><see cref="IPostSignatureValidator"/> - Post-signature policy checks</description></item>
/// </list>
/// <para>
/// A component may implement multiple interfaces if it participates in multiple stages.
/// </para>
/// <para>
/// Before processing begins, the orchestrator calls <see cref="IsApplicableTo"/> to pre-filter
/// components, ensuring only applicable components participate in each stage. This allows
/// components to quickly opt-out based on message characteristics (headers, content-type, etc.)
/// without incurring the cost of full validation.
/// </para>
/// </remarks>
public interface IValidationComponent
{
    /// <summary>
    /// Gets a unique name identifying this component for logging and diagnostics.
    /// </summary>
    string ComponentName { get; }

    /// <summary>
    /// Determines whether this component is applicable to the given message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a lightweight check called by the validator orchestrator before processing
    /// to pre-filter components. Implementations should examine message characteristics
    /// such as headers and content-type to determine applicability.
    /// </para>
    /// <para>
    /// Examples:
    /// <list type="bullet">
    /// <item><description>An X.509 resolver checks for x5chain/x5t headers</description></item>
    /// <item><description>An indirect signature validator checks for PayloadHashAlg header or +cose-hash-v content-type</description></item>
    /// <item><description>A key-id resolver checks for kid header</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// This check should be fast and should NOT perform heavy validation, network I/O,
    /// or chain building. Those operations belong in the actual validation methods.
    /// </para>
    /// </remarks>
    /// <param name="message">The COSE Sign1 message to check, or null.</param>
    /// <param name="options">Optional validation options that may affect applicability determination.</param>
    /// <returns><c>true</c> if this component should participate in validation; otherwise, <c>false</c>.</returns>
    bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options = null);
}
