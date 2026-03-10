// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Security.Cryptography.Cose;

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

/// <summary>
/// Extension methods for extracting header data from <see cref="CoseSign1Message"/>.
/// Provides helpers that abstract away differences between direct and indirect signature formats.
/// </summary>
public static class CoseSign1MessageExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string HashLegacyPattern = @"\+hash-([\w_]+)";
        public const string CoseHashVPattern = @"\+cose-hash-v";
        public const string CoapContentTypeFormat = "coap/{0}";
    }

    private static readonly Regex HashLegacyRegex = new(ClassStrings.HashLegacyPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex CoseHashVRegex = new(ClassStrings.CoseHashVPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);

    #region Signature Format Detection

    /// <summary>
    /// Determines if the message uses an indirect signature format.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <returns><see langword="true"/> if the message uses any indirect signature format; otherwise, <see langword="false"/>.</returns>
    public static bool IsIndirectSignature(this CoseSign1Message message)
        => message.GetSignatureFormat() != SignatureFormat.Direct;

    /// <summary>
    /// Determines the signature format type.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <returns>The <see cref="SignatureFormat"/> for the provided message.</returns>
    public static SignatureFormat GetSignatureFormat(this CoseSign1Message message)
    {
        if (message == null)
        {
            return SignatureFormat.Direct;
        }

        // Check for CoseHashEnvelope (has header 258 - payload hash algorithm)
        if (message.ProtectedHeaders.ContainsKey(IndirectSignatureHeaderLabels.PayloadHashAlg))
        {
            return SignatureFormat.IndirectCoseHashEnvelope;
        }

        // Check content-type header for indirect signature markers
        if (message.TryGetHeader(CoseHeaderLabel.ContentType, out string? contentType) &&
            !string.IsNullOrEmpty(contentType))
        {
            if (CoseHashVRegex.IsMatch(contentType))
            {
                return SignatureFormat.IndirectCoseHashV;
            }

            if (HashLegacyRegex.IsMatch(contentType))
            {
                return SignatureFormat.IndirectHashLegacy;
            }
        }

        return SignatureFormat.Direct;
    }

    #endregion

    #region Content Type

    /// <summary>
    /// Gets the logical content type regardless of signature format.
    /// For direct signatures: returns header 3 (content type).
    /// For indirect signatures: returns the pre-image content type.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <param name="contentType">When this method returns, contains the content type if available; otherwise, <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if a content type could be resolved; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetContentType(
        this CoseSign1Message message,
        out string? contentType)
    {
        if (message == null)
        {
            contentType = null;
            return false;
        }

        var format = message.GetSignatureFormat();

        // For indirect signatures, get the pre-image content type
        if (format != SignatureFormat.Direct)
        {
            return message.TryGetIndirectContentType(format, out contentType);
        }

        // For direct signatures, use header 3 as-is
        return message.TryGetHeader(CoseHeaderLabel.ContentType, out contentType);
    }

    /// <summary>
    /// Gets the logical content type for indirect signatures.
    /// For CoseHashEnvelope: returns header 259 (preimage content type).
    /// For CoseHashV: returns header 3 without "+cose-hash-v".
    /// For legacy indirect: returns header 3 without "+hash-*" extension.
    /// </summary>
    private static bool TryGetIndirectContentType(
        this CoseSign1Message message,
        SignatureFormat format,
        out string? contentType)
    {
        switch (format)
        {
            case SignatureFormat.IndirectCoseHashEnvelope:
                // For CoseHashEnvelope, content type is in header 259 (preimage content type)
                return message.TryGetPreImageContentType(out contentType);

            case SignatureFormat.IndirectCoseHashV:
                // For CoseHashV, strip the "+cose-hash-v" extension
                if (message.TryGetHeader(CoseHeaderLabel.ContentType, out string? rawContentType))
                {
                    contentType = CoseHashVRegex.Replace(rawContentType, string.Empty).Trim();
                    return !string.IsNullOrEmpty(contentType);
                }
                contentType = null;
                return false;

            case SignatureFormat.IndirectHashLegacy:
                // For legacy indirect, strip the "+hash-*" extension
                if (message.TryGetHeader(CoseHeaderLabel.ContentType, out rawContentType))
                {
                    contentType = HashLegacyRegex.Replace(rawContentType, string.Empty).Trim();
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
        var label = IndirectSignatureHeaderLabels.PreimageContentType;

        // Try as string first
        if (message.TryGetHeader(label, out contentType, CoseHeaderLocation.Any))
        {
            return true;
        }

        // Try as CoAP int
        if (message.TryGetHeader(label, out int coapContentType, CoseHeaderLocation.Any))
        {
            contentType = string.Format(ClassStrings.CoapContentTypeFormat, coapContentType);
            return true;
        }

        contentType = null;
        return false;
    }

    #endregion

    #region Payload Location

    /// <summary>
    /// Tries to get the payload location for indirect signatures (header 260).
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <param name="payloadLocation">When this method returns, contains the payload location if available; otherwise, <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if a payload location was found; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetPayloadLocation(
        this CoseSign1Message message,
        out string? payloadLocation)
    {
        if (message == null)
        {
            payloadLocation = null;
            return false;
        }

        // Payload location is only meaningful for CoseHashEnvelope format
        if (message.GetSignatureFormat() != SignatureFormat.IndirectCoseHashEnvelope)
        {
            payloadLocation = null;
            return false;
        }

        return message.TryGetHeader(IndirectSignatureHeaderLabels.PayloadLocation, out payloadLocation, CoseHeaderLocation.Any);
    }

    #endregion

    #region Generic Header Access

    /// <summary>
    /// Tries to get a header value as string from protected or unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract the header from.</param>
    /// <param name="label">The header label to look up.</param>
    /// <param name="value">When this method returns, contains the header value if found; otherwise, <see langword="null"/>.</param>
    /// <param name="headerLocation">Specifies which headers to search. Defaults to <see cref="CoseHeaderLocation.Protected"/>.</param>
    /// <returns><see langword="true"/> if the header was found and successfully converted; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out string? value,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        if (message == null)
        {
            value = null;
            return false;
        }

        if (TryGetHeaderValue(message, label, headerLocation, out var headerValue))
        {
            try
            {
                value = headerValue.GetValueAsString();
                return true;
            }
            catch
            {
                value = null;
                return false;
            }
        }

        value = null;
        return false;
    }

    /// <summary>
    /// Tries to get a header value as int from protected or unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract the header from.</param>
    /// <param name="label">The header label to look up.</param>
    /// <param name="value">When this method returns, contains the header value if found; otherwise, default.</param>
    /// <param name="headerLocation">Specifies which headers to search. Defaults to <see cref="CoseHeaderLocation.Protected"/>.</param>
    /// <returns><see langword="true"/> if the header was found and successfully converted; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out int value,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        if (message == null)
        {
            value = default;
            return false;
        }

        if (TryGetHeaderValue(message, label, headerLocation, out var headerValue))
        {
            try
            {
                value = headerValue.GetValueAsInt32();
                return true;
            }
            catch
            {
                value = default;
                return false;
            }
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Tries to get a header value as bytes from protected or unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract the header from.</param>
    /// <param name="label">The header label to look up.</param>
    /// <param name="value">When this method returns, contains the header value if found; otherwise, default.</param>
    /// <param name="headerLocation">Specifies which headers to search. Defaults to <see cref="CoseHeaderLocation.Protected"/>.</param>
    /// <returns><see langword="true"/> if the header was found and successfully converted; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out ReadOnlyMemory<byte> value,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        if (message == null)
        {
            value = default;
            return false;
        }

        if (TryGetHeaderValue(message, label, headerLocation, out var headerValue))
        {
            try
            {
                value = headerValue.GetValueAsBytes();
                return true;
            }
            catch
            {
                value = default;
                return false;
            }
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Tries to get a raw header value from protected or unprotected headers.
    /// </summary>
    private static bool TryGetHeaderValue(
        CoseSign1Message message,
        CoseHeaderLabel label,
        CoseHeaderLocation headerLocation,
        out CoseHeaderValue headerValue)
    {
        // Check protected headers if requested
        if (headerLocation.HasFlag(CoseHeaderLocation.Protected) &&
            message.ProtectedHeaders.TryGetValue(label, out headerValue))
        {
            return true;
        }

        // Check unprotected headers if requested
        if (headerLocation.HasFlag(CoseHeaderLocation.Unprotected) &&
            message.UnprotectedHeaders.TryGetValue(label, out headerValue))
        {
            return true;
        }

        headerValue = default;
        return false;
    }

    /// <summary>
    /// Checks if a header exists in the specified header locations.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to inspect.</param>
    /// <param name="label">The header label to look up.</param>
    /// <param name="headerLocation">Specifies which headers to search. Defaults to <see cref="CoseHeaderLocation.Protected"/>.</param>
    /// <returns><see langword="true"/> if the header exists; otherwise, <see langword="false"/>.</returns>
    public static bool HasHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        if (message == null)
        {
            return false;
        }

        if (headerLocation.HasFlag(CoseHeaderLocation.Protected) &&
            message.ProtectedHeaders.ContainsKey(label))
        {
            return true;
        }

        if (headerLocation.HasFlag(CoseHeaderLocation.Unprotected) &&
            message.UnprotectedHeaders.ContainsKey(label))
        {
            return true;
        }

        return false;
    }

    #endregion
}
