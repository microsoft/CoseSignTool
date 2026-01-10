// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Inspection;

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using CoseSign1.Factories.Indirect;
using CoseSignTool.Output;

/// <summary>
/// Service for inspecting COSE Sign1 messages and extracting information.
/// </summary>
public class CoseInspectionService
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Section titles
        public static readonly string SectionSignatureDetails = "COSE Sign1 Signature Details";
        public static readonly string HeaderProtected = "Protected Headers:";
        public static readonly string HeaderUnprotected = "Unprotected Headers:";
        public static readonly string HeaderCwtClaims = "CWT Claims (SCITT Compliance):";
        public static readonly string HeaderPayload = "Payload:";
        public static readonly string HeaderSignature = "Signature:";

        // Key names
        public static readonly string KeyFile = "File";
        public static readonly string KeySize = "Size";
        public static readonly string KeyAlgorithm = "  Algorithm";
        public static readonly string KeyContentType = "  Content Type";
        public static readonly string KeyCriticalHeaders = "  Critical Headers";
        public static readonly string KeyPreview = "  Preview";
        public static readonly string KeyType = "  Type";
        public static readonly string KeySha256 = "  SHA-256";
        public static readonly string KeyContent = "  Content";
        public static readonly string KeyTotalSize = "  Total Size";
        public static readonly string KeyExtractedSize = "  Extracted Size";
        public static readonly string KeyPayloadSize = "  Size";
        public static readonly string KeyIssuer = "  Issuer (iss)";
        public static readonly string KeySubject = "  Subject (sub)";
        public static readonly string KeyAudience = "  Audience (aud)";
        public static readonly string KeyIssuedAt = "  Issued At (iat)";
        public static readonly string KeyNotBefore = "  Not Before (nbf)";
        public static readonly string KeyExpiration = "  Expiration (exp)";
        public static readonly string KeyCwtId = "  CWT ID (cti)";
        public static readonly string KeyCustomClaims = "  Custom Claims";

        // Formatting helpers
        public static readonly string Indent = "  ";
        public static readonly string FormatKeyValue = "{0}: {1}{2}";

        // Value formats
        public static readonly string FormatBytes = "{0:N0} bytes";
        public static readonly string FormatAlgorithm = "{0} ({1})";
        public static readonly string FormatCustomClaims = "{0} additional claims";
        public static readonly string FormatUnknownAlgorithm = "Unknown ({0})";
        public static readonly string FormatBytesLength = "<{0} bytes>";
        public static readonly string FormatBytesLengthWithHex = "<{0} bytes> [{1}...]";
        public static readonly string FormatHashThumbprint = "{0}: {1}";

        // Display values
        public static readonly string ValueUnableToParse = "<unable to parse>";
        public static readonly string ValuePresent = "<present>";
        public static readonly string ValueBinaryData = "Binary data";
        public static readonly string ValueDetached = "Detached (no embedded payload)";
        public static readonly string ValueProtected = "protected";
        public static readonly string ValueUnprotected = "unprotected";
        public static readonly string ValueExpiredSuffix = " [EXPIRED]";
        public static readonly string ValuePreviewSuffix = "...";

        // Value types
        public static readonly string TypeString = "string";
        public static readonly string TypeUint = "uint";
        public static readonly string TypeInt = "int";
        public static readonly string TypeBytes = "bytes";
        public static readonly string TypeArray = "array";
        public static readonly string TypeMap = "map";
        public static readonly string TypeBool = "bool";
        public static readonly string TypeUnknown = "unknown";
        public static readonly string TypeBinary = "binary";

        // Success messages
        public static readonly string SuccessInspectionComplete = "COSE Sign1 message inspection complete";
        public static readonly string SuccessPayloadExtracted = "Payload extracted to: {0}";

        // Error messages
        public static readonly string ErrorFileNotFound = "File not found: {0}";
        public static readonly string ErrorFailedToDecode = "Failed to decode as COSE Sign1 message: {0}";
        public static readonly string ErrorInvalidFile = "File may not be a valid COSE Sign1 message";
        public static readonly string ErrorInspecting = "Error inspecting COSE message: {0}";
        public static readonly string ErrorReadingFile = "Error reading file: {0}";
        public static readonly string ErrorExtractingPayload = "Failed to extract payload: {0}";

        // Warning messages
        public static readonly string WarningCannotExtract = "Cannot extract payload: signature has no embedded payload (detached)";

        // Info messages
        public static readonly string InfoCertChainUnprotected = "  Certificate Chain found in unprotected headers";
        public static readonly string InfoCertChainProtected = "  Certificate Chain found in protected headers";

        // Algorithm names
        public static readonly string AlgES256 = "ES256 (ECDSA w/ SHA-256)";
        public static readonly string AlgES384 = "ES384 (ECDSA w/ SHA-384)";
        public static readonly string AlgES512 = "ES512 (ECDSA w/ SHA-512)";
        public static readonly string AlgPS256 = "PS256 (RSASSA-PSS w/ SHA-256)";
        public static readonly string AlgPS384 = "PS384 (RSASSA-PSS w/ SHA-384)";
        public static readonly string AlgPS512 = "PS512 (RSASSA-PSS w/ SHA-512)";
        public static readonly string AlgRS256 = "RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)";
        public static readonly string AlgRS384 = "RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)";
        public static readonly string AlgRS512 = "RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)";
        public static readonly string AlgSHA256 = "SHA-256";
        public static readonly string AlgSHA384 = "SHA-384";
        public static readonly string AlgSHA512 = "SHA-512";
        public static readonly string AlgUnknown = "Unknown";

        // Well-known header names
        public static readonly string HeaderNameAlgorithm = "alg (Algorithm)";
        public static readonly string HeaderNameCritical = "crit (Critical)";
        public static readonly string HeaderNameContentType = "content type";
        public static readonly string HeaderNameKeyId = "kid (Key ID)";
        public static readonly string HeaderNameIV = "IV";
        public static readonly string HeaderNamePartialIV = "Partial IV";
        public static readonly string HeaderNameCounterSignature = "counter signature";
        public static readonly string HeaderNameCwtClaims = "CWT Claims";
        public static readonly string HeaderNameX5Chain = "x5chain (Certificate Chain)";
        public static readonly string HeaderNameX5T = "x5t (Certificate Thumbprint)";
        public static readonly string HeaderNameX5U = "x5u (Certificate URL)";
        public static readonly string HeaderNamePayloadHashAlg = "payload-hash-alg (Hash Algorithm)";
        public static readonly string HeaderNamePreimageContentType = "payload-preimage-content-type";
        public static readonly string HeaderNamePayloadLocation = "payload-location";
        public static readonly string HeaderNameScittReceipts = "scitt-receipts";
        public static readonly string HeaderNameScittStatement = "scitt-statement";
        public static readonly string HeaderNameCustom = "Header (custom)";
    }

    private readonly IOutputFormatter Formatter;
    private readonly Func<Stream> StandardOutputProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseInspectionService"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use.</param>
    /// <param name="standardOutputProvider">Optional provider for standard output stream (used for stdout extraction). Defaults to <see cref="Console.OpenStandardOutput()"/>.</param>
    public CoseInspectionService(IOutputFormatter? formatter = null, Func<Stream>? standardOutputProvider = null)
    {
        Formatter = formatter ?? new TextOutputFormatter();
        StandardOutputProvider = standardOutputProvider ?? Console.OpenStandardOutput;
    }

    /// <summary>
    /// Inspects a COSE Sign1 message file and displays its details.
    /// </summary>
    /// <param name="filePath">The path to the COSE Sign1 file.</param>
    /// <param name="extractPayloadPath">Optional path to extract embedded payload to. Use "-" for stdout.</param>
    /// <param name="displayPath">Optional display name for the file path (used when reading from stdin).</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public async Task<int> InspectAsync(string filePath, string? extractPayloadPath = null, string? displayPath = null)
    {
        if (!File.Exists(filePath))
        {
            Formatter.WriteError(string.Format(ClassStrings.ErrorFileNotFound, filePath));
            return (int)ExitCode.FileNotFound;
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(filePath);
            var fileInfo = new FileInfo(filePath);
            var displayName = displayPath ?? fileInfo.FullName;

            Formatter.BeginSection(ClassStrings.SectionSignatureDetails);
            Formatter.WriteKeyValue(ClassStrings.KeyFile, displayName);
            Formatter.WriteKeyValue(ClassStrings.KeySize, string.Format(ClassStrings.FormatBytes, fileInfo.Length));

            // Try to decode as COSE Sign1
            try
            {
                var message = CoseSign1Message.DecodeSign1(bytes);

                // Build structured result for JSON output
                var result = BuildInspectionResult(message, fileInfo);
                Formatter.WriteStructuredData(result);

                // Display protected headers
                DisplayProtectedHeaders(message);

                // Display CWT Claims if present
                DisplayCwtClaims(message);

                // Display unprotected headers
                DisplayUnprotectedHeaders(message);

                // Display payload information
                DisplayPayloadInfo(message);

                // Display signature information
                DisplaySignatureInfo(message);

                // Extract payload if requested
                if (!string.IsNullOrEmpty(extractPayloadPath))
                {
                    await ExtractPayloadAsync(message, extractPayloadPath);
                }

                Formatter.WriteSuccess(ClassStrings.SuccessInspectionComplete);
            }
            catch (CborContentException ex)
            {
                Formatter.WriteWarning(string.Format(ClassStrings.ErrorFailedToDecode, ex.Message));
                Formatter.WriteInfo(ClassStrings.ErrorInvalidFile);
                return (int)ExitCode.InvalidSignature;
            }
            catch (System.Security.Cryptography.CryptographicException ex) when (ex.InnerException is CborContentException cborEx)
            {
                // Some COSE decoding failures are surfaced as CryptographicException with an inner CborContentException.
                // Treat these as invalid signatures for consistency.
                Formatter.WriteWarning(string.Format(ClassStrings.ErrorFailedToDecode, cborEx.Message));
                Formatter.WriteInfo(ClassStrings.ErrorInvalidFile);
                return (int)ExitCode.InvalidSignature;
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                // DecodeSign1 can also throw CryptographicException without an inner CborContentException.
                // These are still decode failures and should be treated as invalid input/signature.
                Formatter.WriteWarning(string.Format(ClassStrings.ErrorFailedToDecode, ex.Message));
                Formatter.WriteInfo(ClassStrings.ErrorInvalidFile);
                return (int)ExitCode.InvalidSignature;
            }
            catch (Exception ex)
            {
                Formatter.WriteError(string.Format(ClassStrings.ErrorInspecting, ex.Message));
                return (int)ExitCode.InspectionFailed;
            }

            Formatter.EndSection();
            return (int)ExitCode.Success;
        }
        catch (Exception ex)
        {
            Formatter.WriteError(string.Format(ClassStrings.ErrorReadingFile, ex.Message));
            return (int)ExitCode.InspectionFailed;
        }
    }

    private CoseInspectionResult BuildInspectionResult(CoseSign1Message message, FileInfo fileInfo)
    {
        var result = new CoseInspectionResult
        {
            File = new FileInformation
            {
                Path = fileInfo.FullName,
                SizeBytes = fileInfo.Length
            },
            ProtectedHeaders = BuildProtectedHeaders(message),
            UnprotectedHeaders = BuildUnprotectedHeaders(message),
            CwtClaims = BuildCwtClaims(message),
            Payload = BuildPayloadInfo(message),
            Signature = BuildSignatureInfo(message),
            Certificates = BuildCertificateInfo(message)
        };

        return result;
    }

    private ProtectedHeadersInfo BuildProtectedHeaders(CoseSign1Message message)
    {
        var info = new ProtectedHeadersInfo();
        var protectedHeaders = message.ProtectedHeaders;

        // Algorithm
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.Algorithm))
        {
            var algValue = protectedHeaders[CoseHeaderLabel.Algorithm];
            try
            {
                var reader = new CborReader(algValue.EncodedValue);
                var algId = reader.ReadInt32();
                info.Algorithm = new AlgorithmInfo
                {
                    Id = algId,
                    Name = GetAlgorithmName(algId)
                };
            }
            catch { }
        }

        // Content Type
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.ContentType))
        {
            var ctValue = protectedHeaders[CoseHeaderLabel.ContentType];
            try
            {
                var reader = new CborReader(ctValue.EncodedValue);
                var state = reader.PeekState();
                if (state == CborReaderState.TextString)
                {
                    info.ContentType = reader.ReadTextString();
                }
                else if (state == CborReaderState.UnsignedInteger || state == CborReaderState.NegativeInteger)
                {
                    info.ContentType = reader.ReadInt32().ToString();
                }
            }
            catch { }
        }

        // Certificate thumbprint (x5t - label 34)
        var x5tLabel = new CoseHeaderLabel(34);
        if (protectedHeaders.ContainsKey(x5tLabel))
        {
            try
            {
                var reader = new CborReader(protectedHeaders[x5tLabel].EncodedValue);
                if (reader.PeekState() == CborReaderState.StartArray)
                {
                    reader.ReadStartArray();
                    var algId = reader.ReadInt32();
                    var thumbprint = reader.ReadByteString();
                    reader.ReadEndArray();
                    info.CertificateThumbprint = new CertificateThumbprintInfo
                    {
                        Algorithm = GetHashAlgorithmName(algId),
                        Value = Convert.ToHexString(thumbprint)
                    };
                }
            }
            catch { }
        }

        // Certificate chain length (x5chain - label 33)
        var x5chainLabel = new CoseHeaderLabel(33);
        if (protectedHeaders.ContainsKey(x5chainLabel))
        {
            try
            {
                var chainValue = protectedHeaders[x5chainLabel];
                var reader = new CborReader(chainValue.EncodedValue);
                var state = reader.PeekState();
                if (state == CborReaderState.StartArray)
                {
                    var count = reader.ReadStartArray();
                    info.CertificateChainLength = count ?? 0;
                }
                else if (state == CborReaderState.ByteString)
                {
                    info.CertificateChainLength = 1;
                }
            }
            catch { }
        }

        // Payload hash algorithm
        if (protectedHeaders.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg))
        {
            try
            {
                var reader = new CborReader(protectedHeaders[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg].EncodedValue);
                var algId = reader.ReadInt32();
                info.PayloadHashAlgorithm = new AlgorithmInfo
                {
                    Id = algId,
                    Name = GetHashAlgorithmName(algId)
                };
            }
            catch { }
        }

        // Preimage content type
        if (protectedHeaders.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType))
        {
            try
            {
                var reader = new CborReader(protectedHeaders[CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType].EncodedValue);
                if (reader.PeekState() == CborReaderState.TextString)
                {
                    info.PreimageContentType = reader.ReadTextString();
                }
            }
            catch { }
        }

        // Payload location
        if (protectedHeaders.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation))
        {
            try
            {
                var reader = new CborReader(protectedHeaders[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation].EncodedValue);
                if (reader.PeekState() == CborReaderState.TextString)
                {
                    info.PayloadLocation = reader.ReadTextString();
                }
            }
            catch { }
        }

        // Collect other headers
        var otherHeaders = new List<HeaderInfo>();
        foreach (var header in protectedHeaders)
        {
            // Skip already processed headers
            if (header.Key.Equals(CoseHeaderLabel.Algorithm) ||
                header.Key.Equals(CoseHeaderLabel.ContentType) ||
                header.Key.Equals(CoseHeaderLabel.CriticalHeaders) ||
                header.Key.Equals(x5tLabel) ||
                header.Key.Equals(x5chainLabel) ||
                header.Key.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg) ||
                header.Key.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType) ||
                header.Key.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation) ||
                header.Key.Equals(CWTClaimsHeaderLabels.CWTClaims))
            {
                continue;
            }

            otherHeaders.Add(BuildHeaderInfo(header.Key, header.Value));
        }

        if (otherHeaders.Count > 0)
        {
            info.OtherHeaders = otherHeaders;
        }

        return info;
    }

    private List<HeaderInfo>? BuildUnprotectedHeaders(CoseSign1Message message)
    {
        var unprotectedHeaders = message.UnprotectedHeaders;
        if (unprotectedHeaders.Count == 0)
        {
            return null;
        }

        var headers = new List<HeaderInfo>();
        foreach (var kvp in unprotectedHeaders)
        {
            headers.Add(BuildHeaderInfo(kvp.Key, kvp.Value));
        }
        return headers;
    }

    private HeaderInfo BuildHeaderInfo(CoseHeaderLabel label, CoseHeaderValue value)
    {
        var info = new HeaderInfo
        {
            Label = GetHeaderName(label),
            LengthBytes = value.EncodedValue.Length
        };

        // Try to get the label ID
        try
        {
            foreach (var (key, _) in WellKnownHeaders)
            {
                if (label.Equals(new CoseHeaderLabel(key)))
                {
                    info.LabelId = key;
                    break;
                }
            }
        }
        catch { }

        // Try to decode the value
        try
        {
            var reader = new CborReader(value.EncodedValue);
            var state = reader.PeekState();

            switch (state)
            {
                case CborReaderState.TextString:
                    info.Value = reader.ReadTextString();
                    info.ValueType = ClassStrings.TypeString;
                    break;
                case CborReaderState.UnsignedInteger:
                    info.Value = reader.ReadUInt64();
                    info.ValueType = ClassStrings.TypeUint;
                    break;
                case CborReaderState.NegativeInteger:
                    info.Value = reader.ReadInt64();
                    info.ValueType = ClassStrings.TypeInt;
                    break;
                case CborReaderState.ByteString:
                    var bytes = reader.ReadByteString();
                    info.ValueType = ClassStrings.TypeBytes;
                    info.LengthBytes = bytes.Length;
                    break;
                case CborReaderState.StartArray:
                    var count = reader.ReadStartArray();
                    info.ValueType = ClassStrings.TypeArray;
                    info.LengthBytes = count ?? 0;
                    break;
                case CborReaderState.StartMap:
                    var mapCount = reader.ReadStartMap();
                    info.ValueType = ClassStrings.TypeMap;
                    info.LengthBytes = mapCount ?? 0;
                    break;
                case CborReaderState.Boolean:
                    info.Value = reader.ReadBoolean();
                    info.ValueType = ClassStrings.TypeBool;
                    break;
                default:
                    info.ValueType = ClassStrings.TypeUnknown;
                    break;
            }
        }
        catch
        {
            info.ValueType = ClassStrings.TypeBinary;
        }

        return info;
    }

    private CwtClaimsInfo? BuildCwtClaims(CoseSign1Message message)
    {
        if (!message.ProtectedHeaders.TryGetCwtClaims(out var claims) || claims == null)
        {
            return null;
        }

        var info = new CwtClaimsInfo();

        if (!string.IsNullOrEmpty(claims.Issuer))
        {
            info.Issuer = claims.Issuer;
        }

        if (!string.IsNullOrEmpty(claims.Subject))
        {
            info.Subject = claims.Subject;
        }

        if (!string.IsNullOrEmpty(claims.Audience))
        {
            info.Audience = claims.Audience;
        }

        if (claims.IssuedAt.HasValue)
        {
            info.IssuedAt = claims.IssuedAt.Value.ToString(AssemblyStrings.Formats.DateTimeUtc);
            info.IssuedAtUnix = claims.IssuedAt.Value.ToUnixTimeSeconds();
        }

        if (claims.NotBefore.HasValue)
        {
            info.NotBefore = claims.NotBefore.Value.ToString(AssemblyStrings.Formats.DateTimeUtc);
            info.NotBeforeUnix = claims.NotBefore.Value.ToUnixTimeSeconds();
        }

        if (claims.ExpirationTime.HasValue)
        {
            var expiry = claims.ExpirationTime.Value;
            info.ExpirationTime = expiry.ToString(AssemblyStrings.Formats.DateTimeUtc);
            info.ExpirationTimeUnix = expiry.ToUnixTimeSeconds();
            info.IsExpired = expiry < DateTimeOffset.UtcNow;
        }

        if (claims.CwtId != null && claims.CwtId.Length > 0)
        {
            info.CwtId = Convert.ToHexString(claims.CwtId);
        }

        if (claims.CustomClaims.Count > 0)
        {
            info.CustomClaimsCount = claims.CustomClaims.Count;
        }

        return info;
    }

    private PayloadInfo BuildPayloadInfo(CoseSign1Message message)
    {
        var payload = message.Content;
        var info = new PayloadInfo
        {
            IsEmbedded = payload.HasValue && payload.Value.Length > 0
        };

        if (info.IsEmbedded)
        {
            info.SizeBytes = payload.Value.Length;
            info.IsText = IsLikelyText(payload.Value.Span);

            if (info.IsText == true)
            {
                int previewLength = Math.Min(100, payload.Value.Length);
                var preview = System.Text.Encoding.UTF8.GetString(payload.Value.Span.Slice(0, previewLength));
                if (payload.Value.Length > 100)
                {
                    preview += ClassStrings.ValuePreviewSuffix;
                }
                info.Preview = preview;
            }
            else
            {
                info.Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload.Value.Span));
            }
        }

        return info;
    }

    private SignatureInfo BuildSignatureInfo(CoseSign1Message message)
    {
        var encoded = message.Encode();
        var info = new SignatureInfo
        {
            TotalSizeBytes = encoded.Length
        };

        var x5chainLabel = new CoseHeaderLabel(33);
        if (message.UnprotectedHeaders.ContainsKey(x5chainLabel))
        {
            info.CertificateChainLocation = ClassStrings.ValueUnprotected;
        }
        else if (message.ProtectedHeaders.ContainsKey(x5chainLabel))
        {
            info.CertificateChainLocation = ClassStrings.ValueProtected;
        }

        return info;
    }

    private List<CertificateInfo>? BuildCertificateInfo(CoseSign1Message message)
    {
        var x5chainLabel = new CoseHeaderLabel(33);
        CoseHeaderValue? chainValue = null;

        if (message.ProtectedHeaders.ContainsKey(x5chainLabel))
        {
            chainValue = message.ProtectedHeaders[x5chainLabel];
        }
        else if (message.UnprotectedHeaders.ContainsKey(x5chainLabel))
        {
            chainValue = message.UnprotectedHeaders[x5chainLabel];
        }

        if (chainValue == null)
        {
            return null;
        }

        var certs = new List<CertificateInfo>();

        try
        {
            var reader = new CborReader(chainValue.Value.EncodedValue);
            var state = reader.PeekState();

            var certBytes = new List<byte[]>();
            if (state == CborReaderState.StartArray)
            {
                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                {
                    certBytes.Add(reader.ReadByteString());
                }
            }
            else if (state == CborReaderState.ByteString)
            {
                certBytes.Add(reader.ReadByteString());
            }

            foreach (var certData in certBytes)
            {
                try
                {
                    using var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certData);
                    certs.Add(new CertificateInfo
                    {
                        Subject = cert.Subject,
                        Issuer = cert.Issuer,
                        SerialNumber = cert.SerialNumber,
                        Thumbprint = cert.Thumbprint,
                        NotBefore = cert.NotBefore.ToString(AssemblyStrings.Formats.DateTimeUtc),
                        NotAfter = cert.NotAfter.ToString(AssemblyStrings.Formats.DateTimeUtc),
                        IsExpired = cert.NotAfter < DateTime.UtcNow,
                        KeyAlgorithm = cert.GetKeyAlgorithm(),
                        SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName
                    });
                }
                catch
                {
                    // Skip malformed certificates
                }
            }
        }
        catch { }

        return certs.Count > 0 ? certs : null;
    }

    private void DisplayProtectedHeaders(CoseSign1Message message)
    {
        Formatter.WriteInfo(ClassStrings.HeaderProtected);

        var protectedHeaders = message.ProtectedHeaders;

        // Algorithm
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.Algorithm))
        {
            var algValue = protectedHeaders[CoseHeaderLabel.Algorithm];
            try
            {
                var reader = new CborReader(algValue.EncodedValue);
                var algId = reader.ReadInt32();
                var algName = GetAlgorithmName(algId);
                Formatter.WriteKeyValue(ClassStrings.KeyAlgorithm, string.Format(ClassStrings.FormatAlgorithm, algId, algName));
            }
            catch
            {
                Formatter.WriteKeyValue(ClassStrings.KeyAlgorithm, ClassStrings.ValueUnableToParse);
            }
        }

        // Content Type
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.ContentType))
        {
            var ctValue = protectedHeaders[CoseHeaderLabel.ContentType];
            try
            {
                var reader = new CborReader(ctValue.EncodedValue);
                var state = reader.PeekState();
                if (state == CborReaderState.TextString)
                {
                    Formatter.WriteKeyValue(ClassStrings.KeyContentType, reader.ReadTextString());
                }
                else if (state == CborReaderState.UnsignedInteger || state == CborReaderState.NegativeInteger)
                {
                    Formatter.WriteKeyValue(ClassStrings.KeyContentType, reader.ReadInt32().ToString());
                }
            }
            catch
            {
                Formatter.WriteKeyValue(ClassStrings.KeyContentType, ClassStrings.ValueUnableToParse);
            }
        }

        // Critical Headers
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.CriticalHeaders))
        {
            Formatter.WriteKeyValue(ClassStrings.KeyCriticalHeaders, ClassStrings.ValuePresent);
        }

        // Display other protected headers
        foreach (var header in protectedHeaders)
        {
            // Skip already displayed standard headers
            if (header.Key.Equals(CoseHeaderLabel.Algorithm) ||
                header.Key.Equals(CoseHeaderLabel.ContentType) ||
                header.Key.Equals(CoseHeaderLabel.CriticalHeaders))
            {
                continue;
            }

            string headerName = GetHeaderName(header.Key);
            string headerValue = FormatHeaderValueWithDecode(header.Key, header.Value);
            Formatter.WriteKeyValue(string.Concat(ClassStrings.Indent, headerName), headerValue);
        }
    }

    private void DisplayUnprotectedHeaders(CoseSign1Message message)
    {
        var unprotectedHeaders = message.UnprotectedHeaders;

        if (unprotectedHeaders.Count > 0)
        {
            Formatter.WriteInfo(ClassStrings.HeaderUnprotected);

            foreach (var kvp in unprotectedHeaders)
            {
                string headerName = GetHeaderName(kvp.Key);
                string headerValue = FormatHeaderValue(kvp.Value);
                Formatter.WriteKeyValue(string.Concat(ClassStrings.Indent, headerName), headerValue);
            }
        }
    }

    private void DisplayCwtClaims(CoseSign1Message message)
    {
        // Try to extract CWT Claims from protected headers using extension method
        if (message.ProtectedHeaders.TryGetCwtClaims(out var claims) && claims != null)
        {
            Formatter.WriteInfo(ClassStrings.HeaderCwtClaims);

            if (!string.IsNullOrEmpty(claims.Issuer))
            {
                Formatter.WriteKeyValue(ClassStrings.KeyIssuer, claims.Issuer);
            }

            if (!string.IsNullOrEmpty(claims.Subject))
            {
                Formatter.WriteKeyValue(ClassStrings.KeySubject, claims.Subject);
            }

            if (!string.IsNullOrEmpty(claims.Audience))
            {
                Formatter.WriteKeyValue(ClassStrings.KeyAudience, claims.Audience);
            }

            if (claims.IssuedAt.HasValue)
            {
                Formatter.WriteKeyValue(ClassStrings.KeyIssuedAt, claims.IssuedAt.Value.ToString(AssemblyStrings.Formats.DateTimeUtc));
            }

            if (claims.NotBefore.HasValue)
            {
                Formatter.WriteKeyValue(ClassStrings.KeyNotBefore, claims.NotBefore.Value.ToString(AssemblyStrings.Formats.DateTimeUtc));
            }

            if (claims.ExpirationTime.HasValue)
            {
                var expiry = claims.ExpirationTime.Value;
                var isExpired = expiry < DateTimeOffset.UtcNow;
                var expiryStr = expiry.ToString(AssemblyStrings.Formats.DateTimeUtc);
                if (isExpired)
                {
                    Formatter.WriteWarning(string.Format(ClassStrings.FormatKeyValue, ClassStrings.KeyExpiration, expiryStr, ClassStrings.ValueExpiredSuffix));
                }
                else
                {
                    Formatter.WriteKeyValue(ClassStrings.KeyExpiration, expiryStr);
                }
            }

            if (claims.CwtId != null && claims.CwtId.Length > 0)
            {
                Formatter.WriteKeyValue(ClassStrings.KeyCwtId, Convert.ToHexString(claims.CwtId));
            }

            if (claims.CustomClaims.Count > 0)
            {
                Formatter.WriteKeyValue(ClassStrings.KeyCustomClaims, string.Format(ClassStrings.FormatCustomClaims, claims.CustomClaims.Count));
            }
        }
    }

    private void DisplayPayloadInfo(CoseSign1Message message)
    {
        Formatter.WriteInfo(ClassStrings.HeaderPayload);

        var payload = message.Content;
        if (payload.HasValue && payload.Value.Length > 0)
        {
            Formatter.WriteKeyValue(ClassStrings.KeyPayloadSize, string.Format(ClassStrings.FormatBytes, payload.Value.Length));

            // Try to detect if it's text
            if (IsLikelyText(payload.Value.Span))
            {
                int previewLength = Math.Min(100, payload.Value.Length);
                var preview = System.Text.Encoding.UTF8.GetString(payload.Value.Span.Slice(0, previewLength));
                if (payload.Value.Length > 100)
                {
                    preview += ClassStrings.ValuePreviewSuffix;
                }
                Formatter.WriteKeyValue(ClassStrings.KeyPreview, preview);
            }
            else
            {
                Formatter.WriteKeyValue(ClassStrings.KeyType, ClassStrings.ValueBinaryData);
                Formatter.WriteKeyValue(ClassStrings.KeySha256, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload.Value.Span)));
            }
        }
        else
        {
            Formatter.WriteKeyValue(ClassStrings.KeyContent, ClassStrings.ValueDetached);
        }
    }

    private async Task ExtractPayloadAsync(CoseSign1Message message, string extractPath)
    {
        var payload = message.Content;

        if (!payload.HasValue || payload.Value.Length == 0)
        {
            Formatter.WriteWarning(ClassStrings.WarningCannotExtract);
            return;
        }

        try
        {
            if (extractPath == AssemblyStrings.IO.StdinIndicator)
            {
                // Write to stdout
                using var stdout = StandardOutputProvider();
                await stdout.WriteAsync(payload.Value.ToArray());
                await stdout.FlushAsync();
            }
            else
            {
                // Write to file
                var fullPath = Path.GetFullPath(extractPath);
                var directory = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                await File.WriteAllBytesAsync(fullPath, payload.Value.ToArray());
                Formatter.WriteSuccess(string.Format(ClassStrings.SuccessPayloadExtracted, fullPath));
                Formatter.WriteKeyValue(ClassStrings.KeyExtractedSize, string.Format(ClassStrings.FormatBytes, payload.Value.Length));
            }
        }
        catch (Exception ex)
        {
            Formatter.WriteError(string.Format(ClassStrings.ErrorExtractingPayload, ex.Message));
        }
    }

    private void DisplaySignatureInfo(CoseSign1Message message)
    {
        Formatter.WriteInfo(ClassStrings.HeaderSignature);
        var encoded = message.Encode();
        Formatter.WriteKeyValue(ClassStrings.KeyTotalSize, string.Format(ClassStrings.FormatBytes, encoded.Length));

        // Try to extract certificate chain from unprotected headers (x5chain is label 33)
        var x5chainLabel = new CoseHeaderLabel(33);
        if (message.UnprotectedHeaders.ContainsKey(x5chainLabel))
        {
            Formatter.WriteInfo(ClassStrings.InfoCertChainUnprotected);
        }

        // Check protected headers too
        if (message.ProtectedHeaders.ContainsKey(x5chainLabel))
        {
            Formatter.WriteInfo(ClassStrings.InfoCertChainProtected);
        }
    }

    private static string GetAlgorithmName(int algorithm)
    {
        return algorithm switch
        {
            // ECDSA algorithms
            -7 => ClassStrings.AlgES256,
            -35 => ClassStrings.AlgES384,
            -36 => ClassStrings.AlgES512,
            // RSA-PSS algorithms
            -37 => ClassStrings.AlgPS256,
            -38 => ClassStrings.AlgPS384,
            -39 => ClassStrings.AlgPS512,
            // RSA PKCS#1 algorithms
            -257 => ClassStrings.AlgRS256,
            -258 => ClassStrings.AlgRS384,
            -259 => ClassStrings.AlgRS512,
            // Hash algorithms (for payload-hash-alg)
            -16 => ClassStrings.AlgSHA256,
            -43 => ClassStrings.AlgSHA384,
            -44 => ClassStrings.AlgSHA512,
            _ => ClassStrings.AlgUnknown
        };
    }

    private static string GetHashAlgorithmName(int algorithm)
    {
        return algorithm switch
        {
            -16 => ClassStrings.AlgSHA256,
            -43 => ClassStrings.AlgSHA384,
            -44 => ClassStrings.AlgSHA512,
            _ => string.Format(ClassStrings.FormatUnknownAlgorithm, algorithm)
        };
    }

    private static string FormatHeaderValueWithDecode(CoseHeaderLabel label, CoseHeaderValue value)
    {
        try
        {
            var reader = new CborReader(value.EncodedValue);
            var state = reader.PeekState();

            // Try to decode payload-hash-alg as algorithm ID
            if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg))
            {
                if (state == CborReaderState.NegativeInteger || state == CborReaderState.UnsignedInteger)
                {
                    var algId = reader.ReadInt32();
                    return GetHashAlgorithmName(algId);
                }
            }

            // Try to decode preimage-content-type as string
            if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType))
            {
                if (state == CborReaderState.TextString)
                {
                    return reader.ReadTextString();
                }
            }

            // Try to decode payload-location as string
            if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation))
            {
                if (state == CborReaderState.TextString)
                {
                    return reader.ReadTextString();
                }
            }

            // For certificate thumbprint, show as hex
            if (label.Equals(new CoseHeaderLabel(34))) // x5t
            {
                if (state == CborReaderState.StartArray)
                {
                    reader.ReadStartArray();
                    var algId = reader.ReadInt32();
                    var thumbprint = reader.ReadByteString();
                    reader.ReadEndArray();
                    var hashName = GetHashAlgorithmName(algId);
                    return string.Format(ClassStrings.FormatHashThumbprint, hashName, Convert.ToHexString(thumbprint));
                }
            }

            // Generic decoding for simple types
            return state switch
            {
                CborReaderState.TextString => reader.ReadTextString(),
                CborReaderState.UnsignedInteger => reader.ReadUInt64().ToString(),
                CborReaderState.NegativeInteger => reader.ReadInt64().ToString(),
                CborReaderState.ByteString => string.Format(ClassStrings.FormatBytesLength, value.EncodedValue.Length),
                _ => string.Format(ClassStrings.FormatBytesLength, value.EncodedValue.Length)
            };
        }
        catch
        {
            return string.Format(ClassStrings.FormatBytesLength, value.EncodedValue.Length);
        }
    }

    // Well-known COSE header labels (from RFC 9052, RFC 9054, and extensions)
    // Using constants from CoseSign1.Headers library where available
    private static readonly Dictionary<int, string> WellKnownHeaders = new()
    {
        // Standard COSE headers (RFC 9052)
        { 1, ClassStrings.HeaderNameAlgorithm },
        { 2, ClassStrings.HeaderNameCritical },
        { 3, ClassStrings.HeaderNameContentType },
        { 4, ClassStrings.HeaderNameKeyId },
        { 5, ClassStrings.HeaderNameIV },
        { 6, ClassStrings.HeaderNamePartialIV },
        { 7, ClassStrings.HeaderNameCounterSignature },
        // CWT Claims header (RFC 9597) - label 15
        { 15, ClassStrings.HeaderNameCwtClaims },
        // X.509 certificate headers
        { 33, ClassStrings.HeaderNameX5Chain },
        { 34, ClassStrings.HeaderNameX5T },
        { 35, ClassStrings.HeaderNameX5U },
        // COSE Hash Envelope headers (RFC 9054)
        { 258, ClassStrings.HeaderNamePayloadHashAlg },
        { 259, ClassStrings.HeaderNamePreimageContentType },
        { 260, ClassStrings.HeaderNamePayloadLocation },
        // SCITT transparency headers
        { 393, ClassStrings.HeaderNameScittReceipts },
        { 394, ClassStrings.HeaderNameScittStatement },
    };

    private static string GetHeaderName(CoseHeaderLabel label)
    {
        // Check against well-known labels from CoseSign1.Headers constants
        if (label.Equals(CWTClaimsHeaderLabels.CWTClaims))
        {
            return ClassStrings.HeaderNameCwtClaims;
        }
        if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg))
        {
            return ClassStrings.HeaderNamePayloadHashAlg;
        }
        if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType))
        {
            return ClassStrings.HeaderNamePreimageContentType;
        }
        if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation))
        {
            return ClassStrings.HeaderNamePayloadLocation;
        }

        // Check against other well-known headers by comparing equality
        foreach (var (key, name) in WellKnownHeaders)
        {
            if (label.Equals(new CoseHeaderLabel(key)))
            {
                return name;
            }
        }

        // For unknown labels, return a generic description
        return ClassStrings.HeaderNameCustom;
    }

    private static string FormatHeaderValue(CoseHeaderValue value)
    {
        if (value.EncodedValue.Length < 50)
        {
            return string.Format(ClassStrings.FormatBytesLength, value.EncodedValue.Length);
        }
        return string.Format(ClassStrings.FormatBytesLengthWithHex, value.EncodedValue.Length, Convert.ToHexString(value.EncodedValue.Span.Slice(0, 20)));
    }

    private static bool IsLikelyText(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return false;
        }

        // Check if most bytes are printable ASCII or common UTF-8
        int printableCount = 0;
        foreach (byte b in data.Slice(0, Math.Min(1000, data.Length)))
        {
            if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13)
            {
                printableCount++;
            }
        }

        return printableCount > data.Length * 0.8;
    }
}
