﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature;

/// <summary>
/// Stream methods and overloads for the IndirectSignatureFactory class.
/// </summary>
public sealed partial class IndirectSignatureFactory
{
    #region Stream overloads return CoseSign1Message
    #region sync old signature - backwards compatibility
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateIndirectSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignature(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public CoseSign1Message CreateIndirectSignatureFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureFromHash(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureAsync(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureFromHashAsync(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);
    #endregion
    #region new sync signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateIndirectSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                returnBytes: false,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: payload,
                signatureVersion: signatureVersion);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public CoseSign1Message CreateIndirectSignatureFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                returnBytes: false,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: rawHash,
                payloadHashed: true,
                signatureVersion: signatureVersion);
    #endregion
    #region new async signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            Task.FromResult(
                (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                    returnBytes: false,
                    signingKeyProvider: signingKeyProvider,
                    contentType: contentType,
                    streamPayload: payload,
                    signatureVersion: signatureVersion));

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            Task.FromResult(
                (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                    returnBytes: false,
                    signingKeyProvider: signingKeyProvider,
                    contentType: contentType,
                    streamPayload: rawHash,
                    payloadHashed: true,
                    signatureVersion: signatureVersion));
    #endregion
    #endregion

    #region Stream overloads return byte[]
    #region sync old signature - backwards compatibility
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureBytes(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytesFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureBytesFromHash(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);
    #endregion
    #region async old signature - backwards compatibility
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureBytesAsync(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false) =>
            CreateIndirectSignatureBytesFromHashAsync(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope);
    #endregion
    #region new sync signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                returnBytes: true,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: payload,
                payloadHashed: false,
                signatureVersion: signatureVersion);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytesFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                returnBytes: true,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: rawHash,
                payloadHashed: true,
                signatureVersion: signatureVersion);
    #endregion
    #region new async signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            Task.FromResult(
                (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                    returnBytes: true,
                    signingKeyProvider: signingKeyProvider,
                    contentType: contentType,
                    streamPayload: payload,
                    payloadHashed: false,
                    signatureVersion: signatureVersion));

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion) =>
            Task.FromResult(
                (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                    returnBytes: true,
                    signingKeyProvider: signingKeyProvider,
                    contentType: contentType,
                    streamPayload: rawHash,
                    payloadHashed: true,
                    signatureVersion: signatureVersion));
    #endregion
    #endregion
}
