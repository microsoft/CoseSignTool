// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Extensions;

/// <summary>
/// Class which extends <see cref="CoseSign1Message"/> for detached signature use cases.
/// </summary>
/// <remarks>
/// Logging is done through Trace.TraceError and Debug.WriteLine.
/// </remarks>
public static class CoseSign1MessageDetachedSignatureExtensions
{
    private static readonly string AlgorithmGroupName = "algorithm";
    private static readonly Regex HashMimeTypeExtension = new (@$"(?<extension>\+hash-(?<{AlgorithmGroupName}>\w+))", RegexOptions.Compiled);

    /// <summary>
    /// Extracts the hash name from the hash extension within the mime type
    /// </summary>
    /// <param name="this">The COSE Sign1 Message to evaluate</param>
    /// <param name="name">The discovered Hash Algorithm Name from the Content Type Protected Header value of the CoseSign1Message.</param>
    /// <returns>True if successful in extracting a HashAlgorithmName from the Content Type Protected Header; False otherwise.</returns>
    public static bool TryGetDetachedSignatureAlgorithm(this CoseSign1Message @this, out HashAlgorithmName name)
    {
        if(@this == null)
        {
            Trace.TraceError($"{nameof(TryGetDetachedSignatureAlgorithm)} was called on a null CoseSign1Message object");
            return false;
        }

        if(!@this.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType))
        {
            Trace.TraceError($"{nameof(TryGetDetachedSignatureAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the ContentType protected header present.");
            return false;
        }

        string contentType = @this.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString();
        if(string.IsNullOrEmpty(contentType))
        {
            Trace.TraceError($"{nameof(TryGetDetachedSignatureAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the ContentType protected header being a string value.");
            return false;
        }

        Match mimeMatch = HashMimeTypeExtension.Match(contentType);
        if(!mimeMatch.Success)
        {
            Trace.TraceError($"{nameof(TryGetDetachedSignatureAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) with the ContentType protected header being \"{contentType}\" however it did not match the regex pattern \"{HashMimeTypeExtension}\".");
            return false;
        }

        name = new HashAlgorithmName(mimeMatch.Groups[AlgorithmGroupName].Value.ToUpperInvariant());
        Debug.WriteLine($"{nameof(TryGetDetachedSignatureAlgorithm)} extracted hash algorithm name: {name.Name}, returning true");
        return true;
    }

    /// <summary>
    /// Can be used to determine if a given CoseSign1Message is encoded detached signature for an artifact.
    /// </summary>
    /// <param name="this">The COSE Sign1 Message to evaluate.</param>
    /// <returns>True if the COSE Sign1 Message is a encoded detached signature; False otherwise.</returns>
    public static bool IsDetachedSignature(this CoseSign1Message @this) => @this.TryGetDetachedSignatureAlgorithm(out _);

    /// <summary>
    /// Computes if the encoded detached signature within the COSE Sign1 Message object matches the given artifact stream.
    /// </summary>
    /// <param name="this">The COSE Sign1 Message to evaluate.</param>
    /// <param name="artifactStream">The artifact stream to evaluate.</param>
    /// <returns>True if the detached signature in the COSE Sign1 Message matches the signature of the artifact stream; False otherwise.</returns>
    public static bool SignatureMatches(this CoseSign1Message @this, Stream artifactStream)
    {
        if (!@this.TryGetHashAlgorithm(out HashAlgorithm? hasher))
        {
            Trace.TraceError($"{nameof(SignatureMatches)} failed to extract a valid HashAlgorithm from the provided CoseSign1Message[{@this?.GetHashCode()}]");
            return false;
        }
        ReadOnlyMemory<byte> artifactHash = hasher.ComputeHash(artifactStream);
        bool equals = @this.Content.Value.Span.SequenceEqual(artifactHash.Span);
        Debug.WriteLine($"{nameof(SignatureMatches)} compared the two hashes with lengths ({artifactHash.Length},{@this.Content.Value.Length}) for equality and returned {equals}");
        return equals;
    }

    /// <summary>
    /// Computes if the encoded detached signature within the COSE Sign1 Message object matches the given artifact bytes.
    /// </summary>
    /// <param name="this">The COSE Sign1 Message to evaluate.</param>
    /// <param name="artifactBytes">The artifact bytes to evaluate.</param>
    /// <returns>True if the detached signature in the COSE Sign1 Message matches the signature of the artifact bytes; False otherwise.</returns>
    public static bool SignatureMatches(this CoseSign1Message @this, ReadOnlyMemory<byte> artifactBytes)
    {
        if(!@this.TryGetHashAlgorithm(out HashAlgorithm? hasher))
        {
            Trace.TraceError($"{nameof(SignatureMatches)} failed to extract a valid HashAlgorithm from the provided CoseSign1Message[{@this?.GetHashCode()}]");
            return false;
        }

        ReadOnlyMemory<byte> artifactHash = hasher.ComputeHash(artifactBytes.ToArray());
        bool equals = @this.Content.Value.Span.SequenceEqual(artifactHash.Span);
        Debug.WriteLine($"{nameof(SignatureMatches)} compared the two hashes with lengths ({artifactHash.Length},{@this.Content.Value.Length}) for equality and returned {equals}");
        return equals;
    }

    /// <summary>
    /// Extracts a HashAlgoritm used to compute hashes from a given COSE Sign1 Message object if possible.
    /// </summary>
    /// <param name="this">The COSE Sign1 Message to evaluate.</param>
    /// <param name="hasher">Set to a valid HashAlgorithm if return value is True, null otherwise.</param>
    /// <returns>True if a valid HashAlgorithm was returned from the Content Type Protected Header; False otherwise.</returns>
    public static bool TryGetHashAlgorithm(this CoseSign1Message @this, out HashAlgorithm? hasher)
    {
        hasher = null;

        if (!@this.TryGetDetachedSignatureAlgorithm(out HashAlgorithmName algorithmName))
        {
            Trace.TraceError($"{nameof(TryGetHashAlgorithm)} was called on a CoseSign1Message[{@this?.GetHashCode()}] object which did not have a valid hashing algorithm defined");
            return false;
        }

        if (!@this.Content.HasValue)
        {
            Trace.TraceError($"{nameof(TryGetHashAlgorithm)} was called on a CoseSign1Message object which did not have a content value, unable to compute signature match.");
            return false;
        }

        // note that HashAlgorithm.Create() does not throw for names which do not properly map, null is returned.
        hasher = HashAlgorithm.Create(algorithmName.Name);
        if (hasher == null)
        {
            Trace.TraceError($"{nameof(TryGetHashAlgorithm)} was called on a CoseSign1Message object which did not have a hashing algorithm ({algorithmName.Name}) which could be instantiated.");
            return false;
        }
        Debug.WriteLine($"{nameof(TryGetHashAlgorithm)} created a HashAlgorithm from Hash Algorithm Name: {algorithmName.Name}");
        return true;
    }
}
