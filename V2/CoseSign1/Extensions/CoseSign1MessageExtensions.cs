// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Indirect.Extensions;

namespace CoseSign1.Extensions;

/// <summary>
/// Core extension methods for extracting header data from CoseSign1Message.
/// Provides general-purpose header access methods.
/// </summary>
public static class CoseSign1MessageExtensions
{
    /// <summary>
    /// Gets the logical content type regardless of signature format.
    /// For direct signatures: returns header 3
    /// For indirect signatures: delegates to indirect-specific logic
    /// </summary>
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

        // For indirect signatures, delegate to the indirect extension methods
        if (format != SignatureFormat.Direct)
        {
            return message.TryGetIndirectContentType(out contentType);
        }

        // For direct signatures, use header 3 as-is
        return message.TryGetHeader(CoseHeaderLabel.ContentType, out contentType);
    }

    /// <summary>
    /// Tries to get a header value as string from protected or unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract the header from.</param>
    /// <param name="label">The header label to look up.</param>
    /// <param name="value">When this method returns, contains the header value if found; otherwise, null.</param>
    /// <param name="allowUnprotected">If true, also checks unprotected headers when not found in protected headers.</param>
    /// <returns>True if the header was found and successfully converted; otherwise, false.</returns>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out string? value,
        bool allowUnprotected = false)
    {
        if (message == null)
        {
            value = null;
            return false;
        }

        if (TryGetHeaderValue(message, label, allowUnprotected, out var headerValue))
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
    /// <param name="allowUnprotected">If true, also checks unprotected headers when not found in protected headers.</param>
    /// <returns>True if the header was found and successfully converted; otherwise, false.</returns>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out int value,
        bool allowUnprotected = false)
    {
        if (message == null)
        {
            value = default;
            return false;
        }

        if (TryGetHeaderValue(message, label, allowUnprotected, out var headerValue))
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
    /// <param name="allowUnprotected">If true, also checks unprotected headers when not found in protected headers.</param>
    /// <returns>True if the header was found and successfully converted; otherwise, false.</returns>
    public static bool TryGetHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        out ReadOnlyMemory<byte> value,
        bool allowUnprotected = false)
    {
        if (message == null)
        {
            value = default;
            return false;
        }

        if (TryGetHeaderValue(message, label, allowUnprotected, out var headerValue))
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
        bool allowUnprotected,
        out CoseHeaderValue headerValue)
    {
        // Check protected headers first
        if (message.ProtectedHeaders.TryGetValue(label, out headerValue))
        {
            return true;
        }

        // Check unprotected if allowed
        if (allowUnprotected && message.UnprotectedHeaders.TryGetValue(label, out headerValue))
        {
            return true;
        }

        headerValue = default;
        return false;
    }

    /// <summary>
    /// Checks if a header exists in protected headers (and optionally unprotected).
    /// </summary>
    public static bool HasHeader(
        this CoseSign1Message message,
        CoseHeaderLabel label,
        bool allowUnprotected = false)
    {
        if (message == null)
        {
            return false;
        }

        if (message.ProtectedHeaders.ContainsKey(label))
        {
            return true;
        }

        if (allowUnprotected && message.UnprotectedHeaders.ContainsKey(label))
        {
            return true;
        }

        return false;
    }
}