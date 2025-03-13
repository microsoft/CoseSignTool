// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature.Extensions;

/// <summary>
/// Extensions for <see cref="CoseSign1Message"/> to support COSE Hash V.
/// </summary>
public static class CoseSign1MessageCoseHashVExtensions
{
    /// <summary>
    /// Regex to match the +cose-hash-v content/mime type extension.
    /// </summary>
    private static readonly Regex CoseHashVMimeTypeExtension = new(@$"\+cose-hash-v", RegexOptions.Compiled);

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
    internal static bool SignatureMatchesInternalCoseHashV(this CoseSign1Message @this, ReadOnlyMemory<byte>? artifactBytes = null, Stream? artifactStream = null)
    {
        CoseHashV hashStructure = CoseHashV.Deserialize(@this.Content.Value);
        return artifactStream != null
                              ? hashStructure.ContentMatches(artifactStream)
                              : hashStructure.ContentMatches(artifactBytes!.Value);
    }
}
