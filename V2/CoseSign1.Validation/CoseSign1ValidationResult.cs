// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Validation.Results;

/// <summary>
/// Captures the staged results of validating a COSE Sign1 message.
/// </summary>
public sealed class CoseSign1ValidationResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1ValidationResult"/> class.
    /// </summary>
    /// <param name="resolution">The result of the key material resolution stage.</param>
    /// <param name="trust">The result of the signing key trust stage.</param>
    /// <param name="signature">The result of the signature verification stage.</param>
    /// <param name="postSignaturePolicy">The result of the post-signature validation stage.</param>
    /// <param name="overall">The overall result.</param>
    public CoseSign1ValidationResult(
        ValidationResult resolution,
        ValidationResult trust,
        ValidationResult signature,
        ValidationResult postSignaturePolicy,
        ValidationResult overall)
    {
        Resolution = resolution;
        Trust = trust;
        Signature = signature;
        PostSignaturePolicy = postSignaturePolicy;
        Overall = overall;
    }

    /// <summary>
    /// Gets the result of the key material resolution stage.
    /// </summary>
    public ValidationResult Resolution { get; }

    /// <summary>
    /// Gets the result of the signing key trust stage.
    /// </summary>
    public ValidationResult Trust { get; }

    /// <summary>
    /// Gets the result of the signature verification stage.
    /// </summary>
    public ValidationResult Signature { get; }

    /// <summary>
    /// Gets the result of the post-signature validation stage.
    /// </summary>
    public ValidationResult PostSignaturePolicy { get; }

    /// <summary>
    /// Overall validation result.
    /// </summary>
    public ValidationResult Overall { get; }
}
