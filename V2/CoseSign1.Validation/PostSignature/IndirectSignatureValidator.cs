// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.PostSignature;

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text.RegularExpressions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Post-signature validator that verifies indirect signature payload hash matches.
/// </summary>
/// <remarks>
/// <para>
/// Indirect signatures contain a hash of the payload rather than the payload itself.
/// This validator supports three indirect signature formats:
/// </para>
/// <list type="number">
/// <item><description><b>COSE Hash Envelope (RFC 9054)</b>: Uses PayloadHashAlg header (258) to indicate hash algorithm</description></item>
/// <item><description><b>COSE Hash V</b>: Uses content-type with +cose-hash-v extension, content is a CBOR-encoded hash structure</description></item>
/// <item><description><b>Content-Type Hash Extension</b>: Uses content-type with +hash-sha256 (or similar) extension</description></item>
/// </list>
/// <para>
/// When validation succeeds, the validator confirms the hash of the provided payload matches
/// the hash embedded in the signed message. This ensures the payload content was not modified
/// after signing.
/// </para>
/// </remarks>
public sealed partial class IndirectSignatureValidator : IPostSignatureValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ValidatorName = "IndirectSignatureValidator";

        // Regex pattern for extracting algorithm from content-type
        public const string HashMimeTypePattern = @"\+hash-(?<algorithm>[\w_]+)";
        public const string AlgorithmGroupName = "algorithm";

        // Validation result messages
        public const string NotApplicableReason = "Message is not an indirect signature";
        public const string ErrorPayloadMissing = "Indirect signature requires payload for hash validation, but no payload was provided";
        public const string ErrorPayloadMismatch = "Indirect signature payload hash does not match the signed hash value";

        // Error codes
        public const string ErrorCodePayloadMissing = "INDIRECT_SIGNATURE_PAYLOAD_MISSING";
        public const string ErrorCodePayloadMismatch = "INDIRECT_SIGNATURE_PAYLOAD_MISMATCH";

        // Metadata keys
        public const string MetadataKeySignatureType = "IndirectSignatureType";
        public const string MetadataKeyPayloadHashValidated = "PayloadHashValidated";

        // Log messages for internal diagnostics
        public const string LogHashAlgorithmFailed = "Failed to get hash algorithm from PayloadHashAlg header";
        public const string LogNoContent = "Message has no content (embedded hash)";
        public const string LogNoContentCoseHashV = "Message has no content for COSE Hash V";
        public const string LogInvalidCoseHashVStructure = "Invalid COSE Hash V structure: expected array with at least 2 elements";
        public const string LogUnsupportedCoseHashVAlgorithm = "Unsupported COSE Hash V algorithm: {0}";
        public const string LogFailedParseCoseHashV = "Failed to parse COSE Hash V structure";
        public const string LogUnsupportedHashAlgorithm = "Unsupported hash algorithm in content-type: {0}";
        public const string LogNoContentHashComparison = "Message has no content for hash comparison";

        // Hash algorithm name constants for string normalization
        public const string AlgSHA256 = "SHA256";
        public const string AlgSHA384 = "SHA384";
        public const string AlgSHA512 = "SHA512";
        public const string AlgSHA1 = "SHA1";
        public const string Dash = "-";
        public const string Underscore = "_";
    }

    /// <summary>
    /// COSE algorithm identifiers for hash algorithms from IANA registry.
    /// </summary>
    internal enum CoseHashAlgorithm : long
    {
        /// <summary>SHA-256 hash algorithm (-16).</summary>
        SHA256 = -16,

        /// <summary>SHA-384 hash algorithm (-43).</summary>
        SHA384 = -43,

        /// <summary>SHA-512 hash algorithm (-44).</summary>
        SHA512 = -44,
    }

    private static readonly Regex HashMimeTypeExtension = new(
        ClassStrings.HashMimeTypePattern,
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly ILogger<IndirectSignatureValidator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="IndirectSignatureValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public IndirectSignatureValidator(ILogger<IndirectSignatureValidator>? logger = null)
    {
        Logger = logger ?? NullLogger<IndirectSignatureValidator>.Instance;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var message = context.Message;
        var options = context.Options;

        // Detect indirect signature type using the shared extension
        var signatureFormat = message.GetSignatureFormat();

        if (signatureFormat == SignatureFormat.Direct)
        {
            LogNotIndirectSignature();
            return ValidationResult.NotApplicable(ClassStrings.ValidatorName, ClassStrings.NotApplicableReason);
        }

        LogIndirectSignatureDetected(signatureFormat.ToString());

        // Need payload to validate hash
        if (options.DetachedPayload == null)
        {
            LogPayloadMissing();
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorPayloadMissing,
                ClassStrings.ErrorCodePayloadMissing);
        }

        // Reset stream position if seekable
        if (options.DetachedPayload.CanSeek)
        {
            options.DetachedPayload.Position = 0;
        }

        // Validate based on signature type
        bool matches = signatureFormat switch
        {
            SignatureFormat.IndirectCoseHashEnvelope => ValidateCoseHashEnvelope(message, options.DetachedPayload),
            SignatureFormat.IndirectCoseHashV => ValidateCoseHashV(message, options.DetachedPayload),
            SignatureFormat.IndirectHashLegacy => ValidateContentTypeHashExtension(message, options.DetachedPayload),
            _ => false
        };

        if (!matches)
        {
            LogPayloadHashMismatch(signatureFormat.ToString());
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorPayloadMismatch,
                ClassStrings.ErrorCodePayloadMismatch);
        }

        LogPayloadHashValidated(signatureFormat.ToString());
        return ValidationResult.Success(ClassStrings.ValidatorName, new Dictionary<string, object>
        {
            [ClassStrings.MetadataKeySignatureType] = signatureFormat.ToString(),
            [ClassStrings.MetadataKeyPayloadHashValidated] = true
        });
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(
        IPostSignatureValidationContext context,
        CancellationToken cancellationToken = default)
    {
        // Validation is CPU-bound (hash computation), so just run synchronously
        return Task.FromResult(Validate(context));
    }

    #region COSE Hash Envelope Validation

    private bool ValidateCoseHashEnvelope(CoseSign1Message message, Stream payload)
    {
        if (!TryGetPayloadHashAlgorithm(message, out var hasher) || hasher == null)
        {
            Logger.LogWarning(ClassStrings.LogHashAlgorithmFailed);
            return false;
        }

        using (hasher)
        {
            if (!message.Content.HasValue)
            {
                Logger.LogWarning(ClassStrings.LogNoContent);
                return false;
            }

            var computedHash = hasher.ComputeHash(payload);
            var embeddedHash = message.Content.Value.Span;

            return computedHash.AsSpan().SequenceEqual(embeddedHash);
        }
    }

    private static bool TryGetPayloadHashAlgorithm(CoseSign1Message message, out HashAlgorithm? hasher)
    {
        hasher = null;

        // Use the shared header label from Abstractions
        if (!message.TryGetHeader(IndirectSignatureHeaderLabels.PayloadHashAlg, out int algId))
        {
            return false;
        }

        hasher = (CoseHashAlgorithm)algId switch
        {
            CoseHashAlgorithm.SHA256 => SHA256.Create(),
            CoseHashAlgorithm.SHA384 => SHA384.Create(),
            CoseHashAlgorithm.SHA512 => SHA512.Create(),
            _ => null
        };

        return hasher != null;
    }

    #endregion

    #region COSE Hash V Validation

    private bool ValidateCoseHashV(CoseSign1Message message, Stream payload)
    {
        if (!message.Content.HasValue)
        {
            Logger.LogWarning(ClassStrings.LogNoContentCoseHashV);
            return false;
        }

        try
        {
            // Parse the COSE Hash V structure from message content
            var reader = new CborReader(message.Content.Value);

            // COSE Hash V is an array: [algorithm, hash, ?location, ?additionalData]
            var arrayLength = reader.ReadStartArray();
            if (arrayLength == null || arrayLength < 2)
            {
                Logger.LogWarning(ClassStrings.LogInvalidCoseHashVStructure);
                return false;
            }

            // Read algorithm (negative integer for COSE algorithms)
            var algorithm = (CoseHashAlgorithm)reader.ReadInt64();

            // Read hash value
            var hashValue = reader.ReadByteString();

            // Create hash algorithm and compute
            using var hasher = algorithm switch
            {
                CoseHashAlgorithm.SHA256 => SHA256.Create(),
                CoseHashAlgorithm.SHA384 => SHA384.Create(),
                CoseHashAlgorithm.SHA512 => SHA512.Create(),
                _ => null as HashAlgorithm
            };

            if (hasher == null)
            {
                Logger.LogWarning(ClassStrings.LogUnsupportedCoseHashVAlgorithm, algorithm);
                return false;
            }

            var computedHash = hasher.ComputeHash(payload);
            return computedHash.SequenceEqual(hashValue);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, ClassStrings.LogFailedParseCoseHashV);
            return false;
        }
    }

    #endregion

    #region Content-Type Hash Extension Validation

    private bool ValidateContentTypeHashExtension(CoseSign1Message message, Stream payload)
    {
        // Use the shared extension method to get content type
        if (!message.TryGetHeader(CoseHeaderLabel.ContentType, out string? contentType) ||
            string.IsNullOrEmpty(contentType))
        {
            return false;
        }

        var match = HashMimeTypeExtension.Match(contentType);
        if (!match.Success)
        {
            return false;
        }

        var algorithmName = match.Groups[ClassStrings.AlgorithmGroupName].Value.ToUpperInvariant();

        // Create hash algorithm based on the name in the content-type
        using var hasher = CreateHashAlgorithmFromName(algorithmName);
        if (hasher == null)
        {
            Logger.LogWarning(ClassStrings.LogUnsupportedHashAlgorithm, algorithmName);
            return false;
        }

        if (!message.Content.HasValue)
        {
            Logger.LogWarning(ClassStrings.LogNoContentHashComparison);
            return false;
        }

        var computedHash = hasher.ComputeHash(payload);
        var embeddedHash = message.Content.Value.Span;

        return computedHash.AsSpan().SequenceEqual(embeddedHash);
    }

    private static HashAlgorithm? CreateHashAlgorithmFromName(string algorithmName)
    {
        // Normalize common variations (remove dashes and underscores)
        var normalized = algorithmName.Replace(ClassStrings.Dash, string.Empty).Replace(ClassStrings.Underscore, string.Empty);
        return normalized switch
        {
            ClassStrings.AlgSHA256 => SHA256.Create(),
            ClassStrings.AlgSHA384 => SHA384.Create(),
            ClassStrings.AlgSHA512 => SHA512.Create(),
            // CodeQL[cs/weak-crypto]: SHA-1 is used ONLY for validation of existing legacy content,
            // not for creating new signatures. This enables backward compatibility with existing
            // COSE_Hash_V signatures that were created with SHA-1. New signatures should use SHA-256+.
#pragma warning disable CA5350 // Do not use weak cryptographic algorithms - legacy validation only
            ClassStrings.AlgSHA1 => SHA1.Create(),
#pragma warning restore CA5350
            _ => null
        };
    }

    #endregion

    #region Logging

    [LoggerMessage(Level = LogLevel.Debug, Message = "Message is not an indirect signature, skipping validation")]
    private partial void LogNotIndirectSignature();

    [LoggerMessage(Level = LogLevel.Debug, Message = "Detected indirect signature type: {SignatureType}")]
    private partial void LogIndirectSignatureDetected(string signatureType);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Indirect signature requires payload but none was provided")]
    private partial void LogPayloadMissing();

    [LoggerMessage(Level = LogLevel.Warning, Message = "Payload hash mismatch for {SignatureType} indirect signature")]
    private partial void LogPayloadHashMismatch(string signatureType);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Payload hash validated successfully for {SignatureType} indirect signature")]
    private partial void LogPayloadHashValidated(string signatureType);

    #endregion
}
