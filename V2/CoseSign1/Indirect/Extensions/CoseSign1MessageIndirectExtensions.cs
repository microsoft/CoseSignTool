// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Extensions;

namespace CoseSign1.Indirect.Extensions;

/// <summary>
/// Extension methods for indirect signature functionality on CoseSign1Message.
/// Provides methods to determine signature format types.
/// </summary>
public static class CoseSign1MessageIndirectExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string HashLegacyPattern = @"\+hash-([\w_]+)";
        public const string CoseHashVPattern = @"\+cose-hash-v";
        public const string CoapContentTypeFormat = "coap/{0}";
    }

    private static readonly Regex HashLegacyPattern = new(ClassStrings.HashLegacyPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex CoseHashVPattern = new(ClassStrings.CoseHashVPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Determines the signature format type.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <returns>The signature format for the provided message.</returns>
    public static SignatureFormat GetSignatureFormat(this CoseSign1Message message)
    {
        if (message == null)
        {
            return SignatureFormat.Direct;
        }

        // Check for CoseHashEnvelope (has header 258 - payload hash algorithm)
        if (message.ProtectedHeaders.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg))
        {
            return SignatureFormat.IndirectCoseHashEnvelope;
        }

        // Check content-type header for indirect signature markers
        if (message.TryGetHeader(CoseHeaderLabel.ContentType, out string? contentType) &&
            !string.IsNullOrEmpty(contentType))
        {
            if (CoseHashVPattern.IsMatch(contentType))
            {
                return SignatureFormat.IndirectCoseHashV;
            }

            if (HashLegacyPattern.IsMatch(contentType))
            {
                return SignatureFormat.IndirectHashLegacy;
            }
        }

        return SignatureFormat.Direct;
    }

    /// <summary>
    /// Gets the logical content type for indirect signatures.
    /// For CoseHashEnvelope: returns header 259 (preimage content type)
    /// For CoseHashV: returns header 3 without "+cose-hash-v"
    /// For legacy indirect: returns header 3 without "+hash-*" extension
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <param name="contentType">When this method returns, contains the content type if available; otherwise, <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if a content type could be resolved; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetIndirectContentType(
        this CoseSign1Message message,
        out string? contentType)
    {
        if (message == null)
        {
            contentType = null;
            return false;
        }

        var format = message.GetSignatureFormat();

        switch (format)
        {
            case SignatureFormat.IndirectCoseHashEnvelope:
                // For CoseHashEnvelope, content type is in header 259 (preimage content type)
                return message.TryGetPreImageContentType(out contentType);

            case SignatureFormat.IndirectCoseHashV:
                // For CoseHashV, strip the "+cose-hash-v" extension
                if (message.TryGetHeader(CoseHeaderLabel.ContentType, out string? rawContentType))
                {
                    contentType = CoseHashVPattern.Replace(rawContentType, string.Empty).Trim();
                    return !string.IsNullOrEmpty(contentType);
                }
                contentType = null;
                return false;

            case SignatureFormat.IndirectHashLegacy:
                // For legacy indirect, strip the "+hash-*" extension
                if (message.TryGetHeader(CoseHeaderLabel.ContentType, out rawContentType))
                {
                    contentType = HashLegacyPattern.Replace(rawContentType, string.Empty).Trim();
                    return !string.IsNullOrEmpty(contentType);
                }
                contentType = null;
                return false;

            default:
                contentType = null;
                return false;
        }
    }

    /// <summary>
    /// For CoseHashEnvelope: gets preimage content type from header 259.
    /// Handles both string and CoAP int formats.
    /// </summary>
    private static bool TryGetPreImageContentType(
        this CoseSign1Message message,
        out string? contentType)
    {
        var label = CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType;

        // Try as string first
        if (message.TryGetHeader(label, out contentType, allowUnprotected: true))
        {
            return true;
        }

        // Try as CoAP int
        if (message.TryGetHeader(label, out int coapContentType, allowUnprotected: true))
        {
            contentType = string.Format(ClassStrings.CoapContentTypeFormat, coapContentType);
            return true;
        }

        contentType = null;
        return false;
    }

}

/// <summary>
/// Signature format enumeration.
/// </summary>
public enum SignatureFormat
{
    /// <summary>
    /// Standard embedded or detached signature.
    /// </summary>
    Direct,

    /// <summary>
    /// Legacy indirect signature with "+hash-sha256" style content-type extension.
    /// </summary>
    IndirectHashLegacy,

    /// <summary>
    /// Indirect signature with "+cose-hash-v" content-type extension.
    /// </summary>
    IndirectCoseHashV,

    /// <summary>
    /// Indirect signature using CoseHashEnvelope format (has header 258).
    /// </summary>
    IndirectCoseHashEnvelope
}