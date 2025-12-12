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

        // Check protected headers first
        if (message.ProtectedHeaders.TryGetValue(label, out CoseHeaderValue headerValue))
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

        // Check unprotected if allowed
        if (allowUnprotected && message.UnprotectedHeaders.TryGetValue(label, out headerValue))
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

        // Check protected headers first
        if (message.ProtectedHeaders.TryGetValue(label, out CoseHeaderValue headerValue))
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

        // Check unprotected if allowed
        if (allowUnprotected && message.UnprotectedHeaders.TryGetValue(label, out headerValue))
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

        // Check protected headers first
        if (message.ProtectedHeaders.TryGetValue(label, out CoseHeaderValue headerValue))
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

        // Check unprotected if allowed
        if (allowUnprotected && message.UnprotectedHeaders.TryGetValue(label, out headerValue))
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