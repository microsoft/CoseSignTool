// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

/// <summary>
/// Extracts neutral, factual assertions from signing key material.
/// </summary>
/// <remarks>
/// <para>
/// <strong>IMPORTANT:</strong> Assertion providers extract FACTS, not trust judgments.
/// They do not decide whether the facts are "good enough"—that's the policy's job.
/// </para>
/// <para>
/// Examples of assertions an implementation might emit:
/// <list type="bullet">
/// <item><description>"Issuer DN is CN=Contoso CA"</description></item>
/// <item><description>"Certificate is within validity period"</description></item>
/// <item><description>"Key usage includes digitalSignature"</description></item>
/// <item><description>"EKU contains Code Signing"</description></item>
/// </list>
/// </para>
/// <para>
/// Multiple providers can contribute assertions for the same key. The orchestrator
/// aggregates all assertions for policy evaluation.
/// </para>
/// <para>
/// Providers implement <see cref="IValidationComponent.IsApplicableTo"/> to indicate
/// whether they can process a given message. This is checked by the orchestrator before
/// calling <see cref="ExtractAssertions"/>.
/// </para>
/// </remarks>
public interface ISigningKeyAssertionProvider : IValidationComponent
{
    /// <summary>
    /// Extracts assertions from the signing key.
    /// </summary>
    /// <param name="signingKey">The signing key to extract assertions from.</param>
    /// <param name="message">The original message (for context).</param>
/// <param name="options">Optional validation options that may affect assertion extraction.</param>
/// <returns>A list of strongly-typed assertions about the key.</returns>
IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null);

    /// <summary>
    /// Asynchronously extracts assertions from the signing key.
    /// Use this when assertion extraction requires network I/O (e.g., OCSP checks,
    /// fetching CRLs, calling external services).
    /// </summary>
    /// <param name="signingKey">The signing key to extract assertions from.</param>
    /// <param name="message">The original message (for context).</param>
    /// <param name="options">Optional validation options that may affect assertion extraction.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the list of strongly-typed assertions.</returns>
    Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null,
        CancellationToken cancellationToken = default);
}
