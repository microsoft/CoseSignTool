// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Optional capability interface implemented by <see cref="ICoseSigningKeyProvider"/> implementations
/// that let the caller choose the RSA signature padding.
/// </summary>
/// <remarks>
/// <para>
/// The padding is not merely an implementation detail: it selects the COSE algorithm family. PKCS#1
/// v1.5 produces RS256/RS384/RS512 while PSS produces PS256/PS384/PS512, so verifiers and signing
/// services that accept only one family need this to be selectable.
/// </para>
/// <para>
/// Callers should test for this interface rather than depending on a concrete provider type, and fall
/// back to <see cref="RSASignaturePadding.Pss"/> when a provider does not implement it. This keeps the
/// contract in <c>CoseSign1.Abstractions</c> and avoids a breaking change to
/// <see cref="ICoseSigningKeyProvider"/>, which targets netstandard2.0 and therefore cannot carry a
/// default interface implementation.
/// </para>
/// </remarks>
public interface ISupportsRsaSignaturePadding
{
    /// <summary>
    /// Gets the RSA signature padding to use when the signing key is RSA. Ignored for ECDsa keys.
    /// </summary>
    RSASignaturePadding RSASignaturePadding { get; }
}