// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Results;

/// <summary>
/// Context passed to post-signature validators containing outputs from all prior validation stages.
/// </summary>
/// <remarks>
/// <para>
/// This context is populated by the orchestrator (<see cref="ICoseSign1Validator"/>) as it progresses
/// through the validation pipeline. Post-signature validators receive a pre-populated context
/// containing results from resolution, trust, and signature stages.
/// </para>
/// </remarks>
public interface IPostSignatureValidationContext
{
    /// <summary>
    /// Gets the original COSE Sign1 message being validated.
    /// </summary>
    CoseSign1Message Message { get; }

    /// <summary>
    /// Gets the resolved signing key (from stage 1: Key Material Resolution).
    /// </summary>
    /// <remarks>
    /// May be null if key resolution failed (though post-signature validators only run after
    /// successful resolution, trust, and signature verification).
    /// </remarks>
    ISigningKey? ResolvedSigningKey { get; }

    /// <summary>
    /// Gets all trust assertions collected during the trust stage (from stage 2: Key Material Trust).
    /// </summary>
    IReadOnlyList<ISigningKeyAssertion> TrustAssertions { get; }

    /// <summary>
    /// Gets the trust decision from evaluating TrustPolicy against assertions (from stage 2).
    /// </summary>
    TrustDecision TrustDecision { get; }

    /// <summary>
    /// Gets metadata from the signature validation stage (from stage 3: Signature Verification).
    /// </summary>
    /// <remarks>
    /// Contains information about the signature verification process, such as the algorithm used.
    /// </remarks>
    IReadOnlyDictionary<string, object> SignatureMetadata { get; }

    /// <summary>
    /// Gets the validation options used for this validation operation.
    /// </summary>
    /// <remarks>
    /// Provides access to options such as detached payload content, signature-only validation mode,
    /// and associated data. Post-signature validators can use these to perform content validation
    /// (e.g., indirect signature hash verification).
    /// </remarks>
    CoseSign1ValidationOptions Options { get; }
}

/// <summary>
/// Default implementation of <see cref="IPostSignatureValidationContext"/>.
/// </summary>
public sealed class PostSignatureValidationContext : IPostSignatureValidationContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PostSignatureValidationContext"/> class.
    /// </summary>
    /// <param name="message">The COSE Sign1 message being validated.</param>
    /// <param name="trustAssertions">Trust assertions from the trust stage.</param>
    /// <param name="trustDecision">Trust decision from evaluating policy.</param>
    /// <param name="signatureMetadata">Metadata from signature verification.</param>
    /// <param name="options">The validation options for this operation.</param>
    /// <param name="resolvedSigningKey">The resolved signing key, if any.</param>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    public PostSignatureValidationContext(
        CoseSign1Message message,
        IReadOnlyList<ISigningKeyAssertion> trustAssertions,
        TrustDecision trustDecision,
        IReadOnlyDictionary<string, object> signatureMetadata,
        CoseSign1ValidationOptions options,
        ISigningKey? resolvedSigningKey = null)
    {
        Message = message ?? throw new ArgumentNullException(nameof(message));
        TrustAssertions = trustAssertions ?? throw new ArgumentNullException(nameof(trustAssertions));
        TrustDecision = trustDecision;
        SignatureMetadata = signatureMetadata ?? throw new ArgumentNullException(nameof(signatureMetadata));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        ResolvedSigningKey = resolvedSigningKey;
    }

    /// <inheritdoc />
    public CoseSign1Message Message { get; }

    /// <inheritdoc />
    public ISigningKey? ResolvedSigningKey { get; }

    /// <inheritdoc />
    public IReadOnlyList<ISigningKeyAssertion> TrustAssertions { get; }

    /// <inheritdoc />
    public TrustDecision TrustDecision { get; }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, object> SignatureMetadata { get; }

    /// <inheritdoc />
    public CoseSign1ValidationOptions Options { get; }
}

/// <summary>
/// Validator that runs after signature verification with full context from prior stages.
/// </summary>
/// <remarks>
/// <para>
/// Post-signature validators have access to all outputs from previous validation stages.
/// Use this when your validation logic depends on:
/// </para>
/// <list type="bullet">
/// <item><description>The resolved signing key identity</description></item>
/// <item><description>Trust assertions (e.g., different rules for internal vs external signers)</description></item>
/// <item><description>Signature metadata (e.g., algorithm used)</description></item>
/// </list>
/// <para>
/// The <see cref="IPostSignatureValidationContext"/> is populated by the orchestrator
/// (<see cref="ICoseSign1Validator"/>) as it progresses through the validation stages.
/// Post-signature validators do NOT create the context—they receive it.
/// </para>
/// </remarks>
public interface IPostSignatureValidator : IValidationComponent
{
    /// <summary>
    /// Validates the message using context from all prior validation stages.
    /// </summary>
    /// <param name="context">Context containing outputs from resolution, trust, and signature stages.</param>
    /// <returns>Validation result.</returns>
    ValidationResult Validate(IPostSignatureValidationContext context);

    /// <summary>
    /// Asynchronously validates the message using context from all prior validation stages.
    /// Use this when post-signature validation requires network I/O.
    /// </summary>
    /// <param name="context">Context containing outputs from resolution, trust, and signature stages.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the validation result.</returns>
    Task<ValidationResult> ValidateAsync(
        IPostSignatureValidationContext context,
        CancellationToken cancellationToken = default);
}
