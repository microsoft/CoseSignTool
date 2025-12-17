// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;

namespace CoseSign1.Transparent.MST;

/// <summary>
/// Interface for verifying transparent statements from the Code Transparency service.
/// This abstraction allows for mocking the static <see cref="CodeTransparencyClient.VerifyTransparentStatement"/> method in unit tests.
/// </summary>
/// <remarks>
/// The Azure.Security.CodeTransparency SDK provides <see cref="CodeTransparencyClient.VerifyTransparentStatement"/>
/// as a static method, which cannot be mocked using standard mocking frameworks like Moq.
/// This interface wraps that static method to enable testability.
/// </remarks>
public interface ICodeTransparencyVerifier
{
    /// <summary>
    /// Verifies a transparent statement (signed statement with embedded MST receipt).
    /// </summary>
    /// <param name="transparentStatementBytes">The COSE Sign1 encoded transparent statement bytes.</param>
    /// <param name="verificationOptions">Optional verification options for controlling validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <exception cref="InvalidOperationException">Thrown when verification fails due to invalid receipt or configuration.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when cryptographic verification fails.</exception>
    /// <exception cref="System.Formats.Cbor.CborContentException">Thrown when CBOR parsing fails.</exception>
    /// <exception cref="ArgumentException">Thrown when arguments are invalid.</exception>
    void VerifyTransparentStatement(
        byte[] transparentStatementBytes,
        CodeTransparencyVerificationOptions? verificationOptions = null,
        CodeTransparencyClientOptions? clientOptions = null);
}
