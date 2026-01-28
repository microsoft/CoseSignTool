// Copyright (c) Microsoft Corporation.
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
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateIndirectSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignature(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public CoseSign1Message CreateIndirectSignatureFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureFromHash(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureAsync(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<CoseSign1Message> CreateIndirectSignatureFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureFromHashAsync(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);
    #endregion
    #region new sync signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public CoseSign1Message CreateIndirectSignature(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                returnBytes: false,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: payload,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public CoseSign1Message CreateIndirectSignatureFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            (CoseSign1Message)CreateIndirectSignatureWithChecksInternal(
                returnBytes: false,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: rawHash,
                payloadHashed: true,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender);
    #endregion
    #region new async signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <param name="payloadLocation">Optional URI indicating where the payload can be retrieved from. Only applicable for CoseHashEnvelope format.</param>
    /// <returns>A Task which can be awaited which will return a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public async Task<CoseSign1Message> CreateIndirectSignatureAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null,
        CancellationToken cancellationToken = default,
        string? payloadLocation = null) =>
            (CoseSign1Message)await CreateIndirectSignatureWithChecksInternalAsync(
                returnBytes: false,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: payload,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender,
                cancellationToken: cancellationToken,
                payloadLocation: payloadLocation).ConfigureAwait(false);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public async Task<CoseSign1Message> CreateIndirectSignatureFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null,
        CancellationToken cancellationToken = default) =>
            (CoseSign1Message)await CreateIndirectSignatureWithChecksInternalAsync(
                returnBytes: false,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: rawHash,
                payloadHashed: true,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender,
                cancellationToken: cancellationToken).ConfigureAwait(false);
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
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureBytes(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytesFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureBytesFromHash(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);
    #endregion
    #region async old signature - backwards compatibility
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureBytesAsync(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="useOldFormat">True to use the older format - CoseHashV, False to use CoseHashEnvelope format (default).</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        bool useOldFormat = false,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            CreateIndirectSignatureBytesFromHashAsync(
                rawHash: rawHash,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion:
                    useOldFormat
#pragma warning disable CS0618 // Type or member is obsolete
                        ? IndirectSignatureVersion.CoseHashV
#pragma warning restore CS0618 // Type or member is obsolete
                        : IndirectSignatureVersion.CoseHashEnvelope,
                coseHeaderExtender: coseHeaderExtender);
    #endregion
    #region new sync signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytes(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                returnBytes: true,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: payload,
                payloadHashed: false,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public ReadOnlyMemory<byte> CreateIndirectSignatureBytesFromHash(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            (ReadOnlyMemory<byte>)CreateIndirectSignatureWithChecksInternal(
                returnBytes: true,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: rawHash,
                payloadHashed: true,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender);
    #endregion
    #region new async signature
    /// <summary>
    /// Creates a Indirect signature of the specified payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="payload">The payload to create a Indirect signature for.</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    public async Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesAsync(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            (ReadOnlyMemory<byte>)await CreateIndirectSignatureWithChecksInternalAsync(
                returnBytes: true,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: payload,
                payloadHashed: false,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender).ConfigureAwait(false);

    /// <summary>
    /// Creates a Indirect signature of the payload given a hash of the payload returned as a <see cref="CoseSign1Message"/> following the rules in this class description.
    /// </summary>
    /// <param name="rawHash">The raw hash of the payload</param>
    /// <param name="signingKeyProvider">The COSE signing key provider to be used for the signing operation within the <see cref="ICoseSign1MessageFactory"/>.</param>
    /// <param name="contentType">A media type string following https://datatracker.ietf.org/doc/html/rfc6838.</param>
    /// <param name="signatureVersion">The <see cref="IndirectSignatureVersion"/> this factory should create.</param>
    /// <param name="coseHeaderExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>A Task which when completed returns a byte[] representation of a CoseSign1Message which can be used as a Indirect signature validation of the payload.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentException">Hash size does not correspond to any known hash algorithms</exception>
    public async Task<ReadOnlyMemory<byte>> CreateIndirectSignatureBytesFromHashAsync(
        Stream rawHash,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        IndirectSignatureVersion signatureVersion,
        ICoseHeaderExtender? coseHeaderExtender = null) =>
            (ReadOnlyMemory<byte>)await CreateIndirectSignatureWithChecksInternalAsync(
                returnBytes: true,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                streamPayload: rawHash,
                payloadHashed: true,
                signatureVersion: signatureVersion,
                headerExtender: coseHeaderExtender).ConfigureAwait(false);
    #endregion
    #endregion
}
