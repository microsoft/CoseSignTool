// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature;

/// <summary>
/// Methods to create indirect signatures in the COSE Hash V format.
/// </summary>
public sealed partial class IndirectSignatureFactory
{
    /// <summary>
    /// Does the heavy lifting for this class in computing the hash and creating the correct representation of the CoseSign1Message base on input.
    /// </summary>
    /// <param name="returnBytes">True if ReadOnlyMemory<byte> form of CoseSign1Message is to be returned, False for a proper CoseSign1Message</param>
    /// <param name="signingKeyProvider">The signing key provider used for COSE signing operations.</param>
    /// <param name="contentType">The user specified content type.</param>
    /// <param name="streamPayload">If not null, then Stream API's on the CoseSign1MessageFactory are used.</param>
    /// <param name="bytePayload">If streamPayload is null then this must be specified and must not be null and will use the Byte API's on the CoseSign1MesssageFactory</param>
    /// <param name="payloadHashed">True if the payload represents the raw hash</param>
    /// <param name="headerExtender">Optional header extender to add custom headers to the COSE message.</param>
    /// <returns>Either a CoseSign1Message or a ReadOnlyMemory{byte} representing the CoseSign1Message object.</returns>
    /// <exception cref="ArgumentNullException">The contentType parameter was empty or null</exception>
    /// <exception cref="ArgumentNullException">Either streamPayload or bytePayload must be specified, but not both at the same time, or both cannot be null</exception>
    /// <exception cref="ArgumentException">payloadHashed is set, but hash size does not correspond to any known hash algorithms</exception>
    private object CreateIndirectSignatureWithChecksInternalCoseHashVFormat(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false,
        ICoseHeaderExtender? headerExtender = null)
    {
        CoseHashV hash;
        string extendedContentType = ExtendContentTypeCoseHashV(contentType);
        if (!payloadHashed)
        {
            hash = streamPayload != null
                                 ? new CoseHashV(InternalCoseHashAlgorithm, streamPayload)
                                 : new CoseHashV(InternalCoseHashAlgorithm, bytePayload!.Value);
        }
        else
        {
            byte[] rawHash = streamPayload != null
                                           ? streamPayload.GetBytes()
                                           : bytePayload!.Value.ToArray();

            if (rawHash.Length != HashLength)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload length {rawHash.Length} does not correspond to the hash size for {InternalHashAlgorithmName} of {HashLength}.");
            }

            hash = new CoseHashV
            {
                Algorithm = InternalCoseHashAlgorithm,
                HashValue = rawHash
            };
        }

        return returnBytes
               // return the raw bytes if asked
               ? InternalMessageFactory.CreateCoseSign1MessageBytes(
                    hash.Serialize(),
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType,
                    headerExtender: headerExtender)
               // return the CoseSign1Message object
               : InternalMessageFactory.CreateCoseSign1Message(
                    hash.Serialize(),
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType,
                    headerExtender: headerExtender);
    }

    /// <summary>
    /// Method which produces a mime type extension for cose_hash_v
    /// </summary>
    /// <param name="contentType">The content type to append the cose_hash_v extension to if not already appended.</param>
    /// <returns>A string representing the content type with an appended cose_hash_v extension</returns>
    private static string ExtendContentTypeCoseHashV(string contentType)
    {
        // only add the extension mapping, if it's not already present within the contentType
        bool alreadyPresent = contentType.IndexOf("+cose-hash-v", StringComparison.InvariantCultureIgnoreCase) != -1;

        return alreadyPresent
            ? contentType
            : $"{contentType}+cose-hash-v";
    }

    /// <summary>
    /// Async version of CreateIndirectSignatureWithChecksInternalCoseHashVFormat that uses async factory methods.
    /// </summary>
    private async Task<object> CreateIndirectSignatureWithChecksInternalCoseHashVFormatAsync(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false,
        ICoseHeaderExtender? headerExtender = null,
        CancellationToken cancellationToken = default)
    {
        // Check for cancellation before starting expensive hash computation
        cancellationToken.ThrowIfCancellationRequested();
        
        CoseHashV hash;
        string extendedContentType = ExtendContentTypeCoseHashV(contentType);
        if (!payloadHashed)
        {
            // Note: HashAlgorithm.ComputeHashAsync is not available in netstandard2.0
            // For better async support in the future, consider targeting net6.0+ where
            // ComputeHashAsync is available on specific hash algorithm implementations
            hash = streamPayload != null
                                 ? new CoseHashV(InternalCoseHashAlgorithm, streamPayload)
                                 : new CoseHashV(InternalCoseHashAlgorithm, bytePayload!.Value);
        }
        else
        {
            byte[] rawHash = streamPayload != null
                                           ? streamPayload.GetBytes()
                                           : bytePayload!.Value.ToArray();

            if (rawHash.Length != HashLength)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload length {rawHash.Length} does not correspond to the hash size for {InternalHashAlgorithmName} of {HashLength}.");
            }

            hash = new CoseHashV
            {
                Algorithm = InternalCoseHashAlgorithm,
                HashValue = rawHash
            };
        }

        return returnBytes
               // return the raw bytes if asked
               ? await InternalMessageFactory.CreateCoseSign1MessageBytesAsync(
                    hash.Serialize(),
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType,
                    headerExtender: headerExtender,
                    cancellationToken: cancellationToken).ConfigureAwait(false)
               // return the CoseSign1Message object
               : await InternalMessageFactory.CreateCoseSign1MessageAsync(
                    hash.Serialize(),
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType,
                    headerExtender: headerExtender,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
