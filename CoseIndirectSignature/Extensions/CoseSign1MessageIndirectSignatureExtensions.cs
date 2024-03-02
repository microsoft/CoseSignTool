// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature.Extensions;

using CoseIndirectSignature.Exceptions;

/// <summary>
/// Class which extends <see cref="CoseSign1Message"/> for indirect signature use cases.
/// </summary>
/// <remarks>
/// Logging is done through Trace.TraceError and Debug.WriteLine.
/// </remarks>
public static class CoseSign1MessageIndirectSignatureExtensions
{
    private static readonly string AlgorithmGroupName = "algorithm";
    // Regex looks for "+hash-sha256" and will parse it out as a named group of "extension" with value "+hash-sha256" an the algorithm group name of "sha256"
    // Will also work with "+hash-sha3_256"
    private static readonly Regex HashMimeTypeExtension = new(@$"(?<extension>\+hash-(?<{AlgorithmGroupName}>[\w_]+))", RegexOptions.Compiled);
    private static readonly Regex CoseHashVMimeTypeExtension = new(@$"\+cose-hash-v", RegexOptions.Compiled);

    /// <summary>
    /// Lazy populate all known hash algorithms from System.Security.Cryptography into a runtime cache
    /// </summary>
    /// <remarks>This was done as <see cref="HashAlgorithm.Create"/> is obsolete and instead it's recommended to call the Create method on each type directly.</remarks>
    internal static readonly Lazy<Dictionary<string, Type>> HashAlgorithmLookup = new Lazy<Dictionary<string, Type>>(() =>
    {
        Dictionary<string, Type> hashLookup = new();

        foreach (Type hashAlgorithm in FindAllDerivedHashAlgorithms())
        {
            if (hashLookup.ContainsKey(hashAlgorithm.BaseType.Name))
            {
                // ignore derived types of derived types for now.
                continue;
            }

            hashLookup.Add(hashAlgorithm.Name.ToUpperInvariant(), hashAlgorithm);
        }

        return hashLookup;
    });

    /// <summary>
    /// Finds all <see cref="HashAlgorithm"/> derived types within <see cref="System.Security.Cryptography"/> assembly.
    /// </summary>
    /// <returns>An enumerable to types which are derived from <see cref="HashAlgorithm"/></returns>
    private static IEnumerable<Type> FindAllDerivedHashAlgorithms()
    {
        // The type to find all derived implementations from.
        Type baseType = typeof(HashAlgorithm);

        // loop through each type in the assembly containing System.Security.Cryptography.SHA256Managed and grab any type that are derived from the base type
        foreach (Type derivedType in Assembly.GetAssembly(typeof(SHA256Managed)).GetTypes().Where(t => t != baseType && baseType.IsAssignableFrom(t)))
        {
            // return this algorithm.
            yield return derivedType;
        }
    }

    /// <summary>
    /// Method which will create a <see cref="HashAlgorithm"/>
    /// </summary>
    /// <param name="hashAlgorithmName">The name of the intended HashAlgorithm to create.  See Derived Types from https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm?view=netstandard-2.0
    /// for examples names.  I.E. SHA1|SHA256|SHA512|SHA3_256</param>
    /// <returns>A HashAlgorithm which is created from the specified HashAlgorithmName or Null if none matched.</returns>
    public static HashAlgorithm? CreateHashAlgorithmFromName(HashAlgorithmName hashAlgorithmName)
    {
        if (!HashAlgorithmLookup.Value.TryGetValue(hashAlgorithmName.Name.ToUpperInvariant(), out Type hashAlgorithmType))
        {
            return null;
        }

        MethodInfo? methodInfo = hashAlgorithmType.GetMethod("Create", Array.Empty<Type>());
        return methodInfo != null
               ? (HashAlgorithm)methodInfo.Invoke(null, null)
               : null;
    }

    /// <summary>
    /// Checks to see if a COSE Sign1 Message has the Content Type Protected Header set to include +cose-hash-v
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate</param>
    /// <returns>True if +cose-hash-v is found, False otherwise.</returns>
    public static bool TryGetIsCoseHashVContentType(this CoseSign1Message? @this)
    {
        if (@this == null)
        {
            Trace.TraceError($"{nameof(TryGetIsCoseHashVContentType)} was called on a null CoseSign1Message object");
            return false;
        }

        if (@this.Content == null)
        {
            Trace.TraceWarning($"{nameof(TryGetIsCoseHashVContentType)} was called on a detached CoseSign1Message object, which is not valid.");
            return false;
        }

        if (!@this.ProtectedHeaders.TryGetValue(CoseHeaderLabel.ContentType, out CoseHeaderValue contentTypeValue))
        {
            Trace.TraceWarning($"{nameof(TryGetIsCoseHashVContentType)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the ContentType protected header present.");
            return false;
        }

        string contentType = contentTypeValue.GetValueAsString();
        if (string.IsNullOrEmpty(contentType))
        {
            Trace.TraceWarning($"{nameof(TryGetIsCoseHashVContentType)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the ContentType protected header being a string value.");
            return false;
        }

        Match mimeMatch = CoseHashVMimeTypeExtension.Match(contentType);
        return mimeMatch.Success;
    }

    /// <summary>
    /// Extracts the hash algorithm name from the hash extension within the Content Type Protected Header if present.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate</param>
    /// <param name="name">The discovered Hash Algorithm Name from the Content Type Protected Header value of the CoseSign1Message.</param>
    /// <returns>True if successful in extracting a HashAlgorithmName from the Content Type Protected Header; False otherwise.</returns>
    public static bool TryGetIndirectSignatureAlgorithm(this CoseSign1Message? @this, out HashAlgorithmName name)
    {
        if (@this == null)
        {
            Trace.TraceError($"{nameof(TryGetIndirectSignatureAlgorithm)} was called on a null CoseSign1Message object");
            return false;
        }

        if (!@this.ProtectedHeaders.TryGetValue(CoseHeaderLabel.ContentType, out CoseHeaderValue contentTypeValue))
        {
            Trace.TraceWarning($"{nameof(TryGetIndirectSignatureAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the ContentType protected header present.");
            return false;
        }

        string contentType = contentTypeValue.GetValueAsString();
        if (string.IsNullOrEmpty(contentType))
        {
            Trace.TraceWarning($"{nameof(TryGetIndirectSignatureAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) without the ContentType protected header being a string value.");
            return false;
        }

        Match mimeMatch = HashMimeTypeExtension.Match(contentType);
        if (!mimeMatch.Success)
        {
            Trace.TraceWarning($"{nameof(TryGetIndirectSignatureAlgorithm)} was called on a CoseSign1Message object({@this.GetHashCode()}) with the ContentType protected header being \"{contentType}\" however it did not match the regex pattern \"{HashMimeTypeExtension}\".");
            return false;
        }

        name = new HashAlgorithmName(mimeMatch.Groups[AlgorithmGroupName].Value.ToUpperInvariant());
        Debug.WriteLine($"{nameof(TryGetIndirectSignatureAlgorithm)} extracted hash algorithm name: {name.Name}, returning true");
        return true;
    }

    /// <summary>
    /// Determines whether the current CoseSign1Message object includes a Indirect signature.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <returns>True if the CoseSign1Message is a encoded indirect signature; False otherwise.</returns>
    public static bool IsIndirectSignature(this CoseSign1Message? @this) => @this.TryGetIsCoseHashVContentType() || @this.TryGetIndirectSignatureAlgorithm(out _);

    /// <summary>
    /// Computes if the encoded Indirect signature within the CoseSign1Message object matches the given artifact stream.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="artifactStream">The artifact stream to evaluate.</param>
    /// <returns>True if the Indirect signature in the CoseSign1Message matches the signature of the artifact stream; False otherwise.</returns>
    public static bool SignatureMatches(this CoseSign1Message? @this, Stream artifactStream)
        => SignatureMatchesInternal(@this, artifactStream: artifactStream);

    /// <summary>
    /// Computes if the encoded Indirect signature within the CoseSign1Message object matches the given artifact bytes.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="artifactBytes">The artifact bytes to evaluate.</param>
    /// <returns>True if the Indirect signature in the CoseSign1Message matches the signature of the artifact bytes; False otherwise.</returns>
    public static bool SignatureMatches(this CoseSign1Message? @this, ReadOnlyMemory<byte> artifactBytes)
        => SignatureMatchesInternal(@this, artifactBytes: artifactBytes);

    /// <summary>
    /// Computes if the encoded Indirect signature within the CoseSign1Message object matches the given artifact bytes or artifact stream.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="artifactBytes">The artifact bytes to evaluate.</param>
    /// <param name="artifactStream">The artifact stream to evaluate.</param>
    /// <returns>True if the Indirect signature in the CoseSign1Message matches the signature of the artifact bytes; False otherwise.</returns>
    private static bool SignatureMatchesInternal(this CoseSign1Message? @this, ReadOnlyMemory<byte>? artifactBytes = null, Stream? artifactStream = null)
    {
        if(@this.TryGetIsCoseHashVContentType())
        {
            return SignatureMatchesInternalCoseHashV(@this, artifactBytes, artifactStream);
        }
        return SignatureMatchesInternalDirect(@this, artifactBytes, artifactStream);
    }

    /// <summary>
    /// Computes if the encoded Indirect signature within the CoseSign1Message object matches the given artifact bytes or artifact stream.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="artifactBytes">The artifact bytes to evaluate.</param>
    /// <param name="artifactStream">The artifact stream to evaluate.</param>
    /// <returns>True if the Indirect signature in the CoseSign1Message matches the signature of the artifact bytes; False otherwise.</returns>
    private static bool SignatureMatchesInternalDirect(this CoseSign1Message @this, ReadOnlyMemory<byte>? artifactBytes = null, Stream? artifactStream = null)
    {
        if (!@this.TryGetHashAlgorithm(out HashAlgorithm? hasher))
        {
            Trace.TraceError($"{nameof(SignatureMatches)} failed to extract a valid HashAlgorithm from the provided CoseSign1Message[{@this?.GetHashCode()}]");
            return false;
        }

        ReadOnlyMemory<byte> artifactHash = artifactBytes.HasValue
                                            ? hasher!.ComputeHash(artifactBytes.Value.ToArray())
                                            : hasher!.ComputeHash(artifactStream!);

        bool equals = @this!.Content.Value.Span.SequenceEqual(artifactHash.Span);
        Debug.WriteLine($"{nameof(SignatureMatches)} compared the two hashes with lengths ({artifactHash.Length},{@this!.Content.Value.Length}) for equality and returned {equals}");
        return equals;
    }

    /// <summary>
    /// Extracts a HashAlgoritm used to compute hashes from a given CoseSign1Message object if possible.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="hasher">Set to a valid HashAlgorithm if return value is True, null otherwise.</param>
    /// <returns>True if a valid HashAlgorithm was returned from the Content Type Protected Header; False otherwise.</returns>
    public static bool TryGetHashAlgorithm(this CoseSign1Message? @this, out HashAlgorithm? hasher)
    {
        hasher = null;

        if (!@this.TryGetIndirectSignatureAlgorithm(out HashAlgorithmName algorithmName))
        {
            Trace.TraceWarning($"{nameof(TryGetHashAlgorithm)} was called on a CoseSign1Message[{@this?.GetHashCode()}] object which did not have a valid hashing algorithm defined");
            return false;
        }

        if (!@this!.Content.HasValue)
        {
            Trace.TraceWarning($"{nameof(TryGetHashAlgorithm)} was called on a CoseSign1Message object which did not have a content value, unable to compute signature match.");
            return false;
        }

        // note that HashAlgorithm.Create() does not throw for names which do not properly map, null is returned.
        hasher = CreateHashAlgorithmFromName(algorithmName);
        if (hasher == null)
        {
            Trace.TraceWarning($"{nameof(TryGetHashAlgorithm)} was called on a CoseSign1Message object which did not have a hashing algorithm ({algorithmName.Name}) which could be instantiated.");
            return false;
        }
        Debug.WriteLine($"{nameof(TryGetHashAlgorithm)} created a HashAlgorithm from Hash Algorithm Name: {algorithmName.Name}");
        return true;
    }

    /// <summary>
    /// Returns the CoseHashV object contained within the .Content of the CoseSign1Message if it is a CoseHashV encoded message.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    /// <returns>A deserialized CoseHashV object if no errors, an exception otherwise.</returns>
    /// <exception cref="InvalidDataException">Thrown if the CoseSign1Message is not a CoseHashV capable object.</exception>
    /// <exception cref="InvalidCoseDataException">Thrown if the content of this CoseSign1Message cannot be deserialized into a CoseHashV object.</exception>
    public static CoseHashV GetCoseHashV(this CoseSign1Message @this, bool disableValidation = false)
    {
        return !@this.TryGetIsCoseHashVContentType()
            ? throw new InvalidDataException($"The CoseSign1Message[{@this?.GetHashCode()}] object is not a CoseHashV capable object.")
            : CoseHashV.Deserialize(@this!.Content.Value, disableValidation);
    }

    /// <summary>
    /// Returns true and populates indirectHash with the CoseHashV object contained within the .Content of the CoseSign1Message if it is a CoseHashV encoded message, false otherwise.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate.</param>
    /// <param name="disableValidation">True to disable the checks which ensure the decoded algorithm expected hash length and the length of the decoded hash match, False (default) to leave them enabled.</param>
    /// <returns>True if indirectHash is successfully populated, false otherwise.</returns>
    public static bool TryGetCoseHashV(this CoseSign1Message @this, out CoseHashV? indirectHash, bool disableValidation = false)
    {
        indirectHash = null;

        try
        {
            indirectHash = @this.GetCoseHashV(disableValidation: disableValidation);
        }
        catch (Exception ex) when (ex is InvalidDataException || ex is InvalidCoseDataException)
        {
            Trace.TraceWarning($"Attempting to get CoseHashV from CoseSign1Message[{@this?.GetHashCode()}] failed, returning false.");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Leverages the CoseHashV structure path to validate content against the stored indirect hash of the content.
    /// </summary>
    /// <param name="this">The CoseSign1Message to evaluate the CoseHashV structure from .Content</param>
    /// <param name="artifactBytes">The artifact bytes to evaluate.</param>
    /// <param name="artifactStream">The artifact stream to evaluate.</param>
    /// <returns>True if the Indirect signature in the CoseSign1Message matches the signature of the artifact bytes; False otherwise.</returns>
    private static bool SignatureMatchesInternalCoseHashV(this CoseSign1Message @this, ReadOnlyMemory<byte>? artifactBytes = null, Stream? artifactStream = null)
    {
        CoseHashV hashStructure = CoseHashV.Deserialize(@this.Content.Value);
        return artifactStream != null
                              ? hashStructure.ContentMatches(artifactStream)
                              : hashStructure.ContentMatches(artifactBytes!.Value);
    }
}
