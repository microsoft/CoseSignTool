// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature;

/// <summary>
/// Methods to create indirect signatures in the COSE Hash Envelope format.
/// </summary>
public sealed partial class IndirectSignatureFactory
{
    /// <summary>
    /// Does the heavy lifting for this class in computing the hash and creating the correct representation of the CoseSign1Message base on input
    /// for https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/03/
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
    private object CreateIndirectSignatureWithChecksInternalCoseHashEnvelopeFormat(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false,
        ICoseHeaderExtender? headerExtender = null)
    {
        ReadOnlyMemory<byte> hash;
        HashAlgorithmName algoName = InternalHashAlgorithmName;

        if (!payloadHashed)
        {
            hash = streamPayload != null
                                 ? InternalHashAlgorithm.ComputeHash(streamPayload)
                                 : InternalHashAlgorithm.ComputeHash(bytePayload!.Value.ToArray());
        }
        else
        {
            hash = streamPayload != null
                                 ? streamPayload.GetBytes()
                                 : bytePayload!.Value.ToArray();
            try
            {
                algoName = SizeInBytesToAlgorithm[hash.Length];
            }
            catch (KeyNotFoundException e)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload size does not correspond to any known hash sizes in {nameof(HashAlgorithmName)}", e);
            }
        }

        ICoseHeaderExtender effectiveHeaderExtender = headerExtender == null ?
            new CoseHashEnvelopeHeaderExtender(algoName, contentType, null) :
            new CoseSign1.Headers.ChainedCoseHeaderExtender(new[] { headerExtender, new CoseHashEnvelopeHeaderExtender(algoName, contentType, null) });

        return returnBytes
               ? InternalMessageFactory.CreateCoseSign1MessageBytes(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    headerExtender: effectiveHeaderExtender)
               : InternalMessageFactory.CreateCoseSign1Message(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    headerExtender: effectiveHeaderExtender);
    }

    /// <summary>
    /// Async version of CreateIndirectSignatureWithChecksInternalCoseHashEnvelopeFormat that uses async factory methods.
    /// </summary>
    private async Task<object> CreateIndirectSignatureWithChecksInternalCoseHashEnvelopeFormatAsync(
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
        
        ReadOnlyMemory<byte> hash;
        HashAlgorithmName algoName = InternalHashAlgorithmName;

        if (!payloadHashed)
        {
            // Note: HashAlgorithm.ComputeHashAsync is not available in netstandard2.0
            // For better async support in the future, consider targeting net6.0+ where
            // ComputeHashAsync is available on specific hash algorithm implementations
            hash = streamPayload != null
                                 ? InternalHashAlgorithm.ComputeHash(streamPayload)
                                 : InternalHashAlgorithm.ComputeHash(bytePayload!.Value.ToArray());
        }
        else
        {
            hash = streamPayload != null
                                 ? streamPayload.GetBytes()
                                 : bytePayload!.Value.ToArray();
            try
            {
                algoName = SizeInBytesToAlgorithm[hash.Length];
            }
            catch (KeyNotFoundException e)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload size does not correspond to any known hash sizes in {nameof(HashAlgorithmName)}", e);
            }
        }

        ICoseHeaderExtender effectiveHeaderExtender = headerExtender == null ?
            new CoseHashEnvelopeHeaderExtender(algoName, contentType, null) :
            new CoseSign1.Headers.ChainedCoseHeaderExtender(new[] { headerExtender, new CoseHashEnvelopeHeaderExtender(algoName, contentType, null) });

        return returnBytes
               ? await InternalMessageFactory.CreateCoseSign1MessageBytesAsync(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    headerExtender: effectiveHeaderExtender,
                    cancellationToken: cancellationToken).ConfigureAwait(false)
               : await InternalMessageFactory.CreateCoseSign1MessageAsync(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    headerExtender: effectiveHeaderExtender,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
