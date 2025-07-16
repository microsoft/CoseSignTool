// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature;

/// <summary>
/// Methods to create indirect signatures in the original direct hash format.
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
    private object CreateIndirectSignatureWithChecksInternalDirectFormat(
        bool returnBytes,
        ICoseSigningKeyProvider signingKeyProvider,
        string contentType,
        Stream? streamPayload = null,
        ReadOnlyMemory<byte>? bytePayload = null,
        bool payloadHashed = false,
        ICoseHeaderExtender? headerExtender = null)
    {
        ReadOnlyMemory<byte> hash;
        string extendedContentType;
        if (!payloadHashed)
        {
            hash = streamPayload != null
                                 ? InternalHashAlgorithm.ComputeHash(streamPayload)
                                 : InternalHashAlgorithm.ComputeHash(bytePayload!.Value.ToArray());
            extendedContentType = ExtendContentTypeDirect(contentType, HashAlgorithmName);
        }
        else
        {
            hash = streamPayload != null
                                 ? streamPayload.GetBytes()
                                 : bytePayload!.Value.ToArray();
            try
            {
                HashAlgorithmName algoName = SizeInBytesToAlgorithm[hash.Length];
                extendedContentType = ExtendContentTypeDirect(contentType, algoName);
            }
            catch (KeyNotFoundException e)
            {
                throw new ArgumentException($"{nameof(payloadHashed)} is set, but payload size does not correspond to any known hash sizes in {nameof(HashAlgorithmName)}", e);
            }
        }

        return returnBytes
               ? InternalMessageFactory.CreateCoseSign1MessageBytes(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType,
                    headerExtender: headerExtender)
               : InternalMessageFactory.CreateCoseSign1Message(
                    hash,
                    signingKeyProvider,
                    embedPayload: true,
                    contentType: extendedContentType,
                    headerExtender: headerExtender);
    }

    /// <summary>
    /// Method which produces a mime type extension based on the given content type and hash algorithm name.
    /// </summary>
    /// <param name="contentType">The content type to append the hash value to if not already appended.</param>
    /// <param name="algorithmName">The "HashAlgorithmName" to append if not already appended.</param>
    /// <returns>A string representing the content type with an appended hash algorithm</returns>
    private static string ExtendContentTypeDirect(string contentType, HashAlgorithmName algorithmName)
    {
        // extract from the string cache to keep string allocations down.
        string extensionMapping = DirectContentTypeExtensionMap.GetOrAdd(algorithmName.Name, (name) => $"+hash-{name.ToLowerInvariant()}");

        // only add the extension mapping, if it's not already present within the contentType
        bool alreadyPresent = contentType.IndexOf("+hash-", StringComparison.InvariantCultureIgnoreCase) != -1;

        return alreadyPresent
            ? contentType
            : $"{contentType}{extensionMapping}";
    }

    /// <summary>
    /// quick lookup map between algorithm name and mime extension
    /// </summary>
    private static readonly ConcurrentDictionary<string, string> DirectContentTypeExtensionMap = new(
        new Dictionary<string, string>()
        {
            { HashAlgorithmName.SHA256.Name, "+hash-sha256" },
            { HashAlgorithmName.SHA384.Name, "+hash-sha384" },
            { HashAlgorithmName.SHA512.Name, "+hash-sha512" }
        });
}
