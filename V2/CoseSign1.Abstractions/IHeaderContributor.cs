// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions;

/// <summary>
/// Context information provided to header contributors during signing.
/// Includes access to the signing key for header derivation.
/// </summary>
public class HeaderContributorContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="HeaderContributorContext"/> class.
    /// </summary>
    /// <param name="signingContext">The signing context containing payload and related metadata.</param>
    /// <param name="signingKey">The signing key being used for the operation.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingContext"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingKey"/> is <see langword="null"/>.</exception>
    public HeaderContributorContext(SigningContext signingContext, ISigningKey signingKey)
    {
        Guard.ThrowIfNull(signingContext);
        Guard.ThrowIfNull(signingKey);

        SigningContext = signingContext;
        SigningKey = signingKey;
    }

    /// <summary>
    /// Gets the signing context (payload, content type, etc.).
    /// </summary>
    /// <value>The signing context.</value>
    public SigningContext SigningContext { get; }

    /// <summary>
    /// Gets the signing key being used for the operation.
    /// Contributors can access key metadata via SigningKey.Metadata.
    /// </summary>
    /// <value>The signing key.</value>
    public ISigningKey SigningKey { get; }
}

/// <summary>
/// Contributes headers to COSE Sign1 messages with access to the signing context and key.
/// Extends <see cref="ICoseHeaderContributor"/> with Sign1-specific context.
/// IMPORTANT: Contributors are invoked at sign-time, not at service init-time.
/// THREAD-SAFETY: Implementations MUST be thread-safe as they may be called concurrently.
/// Contributors should be immutable or use thread-safe operations.
/// ORDER: The signing service controls the order in which contributors are invoked.
/// </summary>
public interface ICoseSign1HeaderContributor : ICoseHeaderContributor
{
    /// <summary>
    /// Contributes protected headers. Called at sign-time with full context.
    /// MUST be thread-safe - may be called concurrently from multiple threads.
    ///
    /// If MergeStrategy is Custom, this method should check for existing headers
    /// and decide whether to add, skip, or modify them.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    /// <param name="context">Context including signing context and signing key (which provides metadata).</param>
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);

    /// <summary>
    /// Contributes unprotected headers. Called at sign-time with full context.
    /// MUST be thread-safe - may be called concurrently from multiple threads.
    ///
    /// If MergeStrategy is Custom, this method should check for existing headers
    /// and decide whether to add, skip, or modify them.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    /// <param name="context">Context including signing context and signing key (which provides metadata).</param>
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}