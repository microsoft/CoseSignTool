// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseSign1.Interfaces;

using System.IO;

/// <summary>
/// Interface for Factory class to create <see cref="CoseSign1Message"/> objects of various forms.
/// </summary>
public interface ICoseSignatureFactory
{
    /// <summary>
    /// Creates a signature of the specified payload returned as a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="payload">The payload to create a signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>The COSE signature structure as a <see cref="CoseSign1Message"/>.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateCoseSign1Message(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType = "application/cose",
        ICoseHeaderExtender? headerExtender = null);

    /// <summary>
    /// Creates a signature of the specified payload returned as a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="payload">The payload to create a signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>The COSE signature structure as a <see cref="CoseSign1Message"/>.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateCoseSign1Message(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType = "application/cose",
        ICoseHeaderExtender? headerExtender = null);

    /// <summary>
    /// Creates a signature of the specified payload returned as a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="payload">The payload to create a signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>The COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
        ReadOnlyMemory<byte> payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType = "application/cose",
        ICoseHeaderExtender? headerExtender = null);

    /// <summary>
    /// Creates a signature of the specified payload returned as a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <returns>The COSE signature structure as a ReadOnlyMemory block of bytes.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateCoseSign1MessageBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType = "application/cose",
        ICoseHeaderExtender? headerExtender = null);
}