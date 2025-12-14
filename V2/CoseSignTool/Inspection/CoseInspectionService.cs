// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using CoseSign1.Indirect;
using CoseSignTool.Output;

namespace CoseSignTool.Inspection;

/// <summary>
/// Service for inspecting COSE Sign1 messages and extracting information.
/// </summary>
public class CoseInspectionService
{
    private readonly IOutputFormatter Formatter;

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseInspectionService"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use.</param>
    public CoseInspectionService(IOutputFormatter? formatter = null)
    {
        Formatter = formatter ?? new TextOutputFormatter();
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
            Formatter.WriteError($"File not found: {filePath}");
            return (int)ExitCode.FileNotFound;
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(filePath);
            var fileInfo = new FileInfo(filePath);
            var displayName = displayPath ?? fileInfo.FullName;

            Formatter.BeginSection("COSE Sign1 Signature Details");
            Formatter.WriteKeyValue("File", displayName);
            Formatter.WriteKeyValue("Size", $"{fileInfo.Length:N0} bytes");

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

                Formatter.WriteSuccess("COSE Sign1 message inspection complete");
            }
            catch (CborContentException ex)
            {
                Formatter.WriteWarning($"Failed to decode as COSE Sign1 message: {ex.Message}");
                Formatter.WriteInfo("File may not be a valid COSE Sign1 message");
                return (int)ExitCode.InvalidSignature;
            }
            catch (Exception ex)
            {
                Formatter.WriteError($"Error inspecting COSE message: {ex.Message}");
                return (int)ExitCode.InspectionFailed;
            }

            Formatter.EndSection();
            return (int)ExitCode.Success;
        }
        catch (Exception ex)
        {
            Formatter.WriteError($"Error reading file: {ex.Message}");
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
                    info.ValueType = "string";
                    break;
                case CborReaderState.UnsignedInteger:
                    info.Value = reader.ReadUInt64();
                    info.ValueType = "uint";
                    break;
                case CborReaderState.NegativeInteger:
                    info.Value = reader.ReadInt64();
                    info.ValueType = "int";
                    break;
                case CborReaderState.ByteString:
                    var bytes = reader.ReadByteString();
                    info.ValueType = "bytes";
                    info.LengthBytes = bytes.Length;
                    break;
                case CborReaderState.StartArray:
                    var count = reader.ReadStartArray();
                    info.ValueType = "array";
                    info.LengthBytes = count ?? 0;
                    break;
                case CborReaderState.StartMap:
                    var mapCount = reader.ReadStartMap();
                    info.ValueType = "map";
                    info.LengthBytes = mapCount ?? 0;
                    break;
                case CborReaderState.Boolean:
                    info.Value = reader.ReadBoolean();
                    info.ValueType = "bool";
                    break;
                default:
                    info.ValueType = "unknown";
                    break;
            }
        }
        catch
        {
            info.ValueType = "binary";
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
            info.IssuedAt = claims.IssuedAt.Value.ToString("yyyy-MM-dd HH:mm:ss UTC");
            info.IssuedAtUnix = claims.IssuedAt.Value.ToUnixTimeSeconds();
        }

        if (claims.NotBefore.HasValue)
        {
            info.NotBefore = claims.NotBefore.Value.ToString("yyyy-MM-dd HH:mm:ss UTC");
            info.NotBeforeUnix = claims.NotBefore.Value.ToUnixTimeSeconds();
        }

        if (claims.ExpirationTime.HasValue)
        {
            var expiry = claims.ExpirationTime.Value;
            info.ExpirationTime = expiry.ToString("yyyy-MM-dd HH:mm:ss UTC");
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
                    preview += "...";
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
            info.CertificateChainLocation = "unprotected";
        }
        else if (message.ProtectedHeaders.ContainsKey(x5chainLabel))
        {
            info.CertificateChainLocation = "protected";
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
                        NotBefore = cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                        NotAfter = cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss UTC"),
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
        Formatter.WriteInfo("Protected Headers:");

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
                Formatter.WriteKeyValue("  Algorithm", $"{algId} ({algName})");
            }
            catch
            {
                Formatter.WriteKeyValue("  Algorithm", "<unable to parse>");
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
                    Formatter.WriteKeyValue("  Content Type", reader.ReadTextString());
                }
                else if (state == CborReaderState.UnsignedInteger || state == CborReaderState.NegativeInteger)
                {
                    Formatter.WriteKeyValue("  Content Type", reader.ReadInt32().ToString());
                }
            }
            catch
            {
                Formatter.WriteKeyValue("  Content Type", "<unable to parse>");
            }
        }

        // Critical Headers
        if (protectedHeaders.ContainsKey(CoseHeaderLabel.CriticalHeaders))
        {
            Formatter.WriteKeyValue("  Critical Headers", "<present>");
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
            Formatter.WriteKeyValue($"  {headerName}", headerValue);
        }
    }

    private void DisplayUnprotectedHeaders(CoseSign1Message message)
    {
        var unprotectedHeaders = message.UnprotectedHeaders;

        if (unprotectedHeaders.Count > 0)
        {
            Formatter.WriteInfo("Unprotected Headers:");

            foreach (var kvp in unprotectedHeaders)
            {
                string headerName = GetHeaderName(kvp.Key);
                string headerValue = FormatHeaderValue(kvp.Value);
                Formatter.WriteKeyValue($"  {headerName}", headerValue);
            }
        }
    }

    private void DisplayCwtClaims(CoseSign1Message message)
    {
        // Try to extract CWT Claims from protected headers using extension method
        if (message.ProtectedHeaders.TryGetCwtClaims(out var claims) && claims != null)
        {
            Formatter.WriteInfo("CWT Claims (SCITT Compliance):");

            if (!string.IsNullOrEmpty(claims.Issuer))
            {
                Formatter.WriteKeyValue("  Issuer (iss)", claims.Issuer);
            }

            if (!string.IsNullOrEmpty(claims.Subject))
            {
                Formatter.WriteKeyValue("  Subject (sub)", claims.Subject);
            }

            if (!string.IsNullOrEmpty(claims.Audience))
            {
                Formatter.WriteKeyValue("  Audience (aud)", claims.Audience);
            }

            if (claims.IssuedAt.HasValue)
            {
                Formatter.WriteKeyValue("  Issued At (iat)", claims.IssuedAt.Value.ToString("yyyy-MM-dd HH:mm:ss UTC"));
            }

            if (claims.NotBefore.HasValue)
            {
                Formatter.WriteKeyValue("  Not Before (nbf)", claims.NotBefore.Value.ToString("yyyy-MM-dd HH:mm:ss UTC"));
            }

            if (claims.ExpirationTime.HasValue)
            {
                var expiry = claims.ExpirationTime.Value;
                var isExpired = expiry < DateTimeOffset.UtcNow;
                var expiryStr = expiry.ToString("yyyy-MM-dd HH:mm:ss UTC");
                if (isExpired)
                {
                    Formatter.WriteWarning($"  Expiration (exp): {expiryStr} [EXPIRED]");
                }
                else
                {
                    Formatter.WriteKeyValue("  Expiration (exp)", expiryStr);
                }
            }

            if (claims.CwtId != null && claims.CwtId.Length > 0)
            {
                Formatter.WriteKeyValue("  CWT ID (cti)", Convert.ToHexString(claims.CwtId));
            }

            if (claims.CustomClaims.Count > 0)
            {
                Formatter.WriteKeyValue("  Custom Claims", $"{claims.CustomClaims.Count} additional claims");
            }
        }
    }

    private void DisplayPayloadInfo(CoseSign1Message message)
    {
        Formatter.WriteInfo("Payload:");

        var payload = message.Content;
        if (payload.HasValue && payload.Value.Length > 0)
        {
            Formatter.WriteKeyValue("  Size", $"{payload.Value.Length:N0} bytes");

            // Try to detect if it's text
            if (IsLikelyText(payload.Value.Span))
            {
                int previewLength = Math.Min(100, payload.Value.Length);
                var preview = System.Text.Encoding.UTF8.GetString(payload.Value.Span.Slice(0, previewLength));
                if (payload.Value.Length > 100)
                {
                    preview += "...";
                }
                Formatter.WriteKeyValue("  Preview", preview);
            }
            else
            {
                Formatter.WriteKeyValue("  Type", "Binary data");
                Formatter.WriteKeyValue("  SHA-256", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload.Value.Span)));
            }
        }
        else
        {
            Formatter.WriteKeyValue("  Content", "Detached (no embedded payload)");
        }
    }

    private async Task ExtractPayloadAsync(CoseSign1Message message, string extractPath)
    {
        var payload = message.Content;

        if (!payload.HasValue || payload.Value.Length == 0)
        {
            Formatter.WriteWarning("Cannot extract payload: signature has no embedded payload (detached)");
            return;
        }

        try
        {
            if (extractPath == "-")
            {
                // Write to stdout
                using var stdout = Console.OpenStandardOutput();
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
                Formatter.WriteSuccess($"Payload extracted to: {fullPath}");
                Formatter.WriteKeyValue("  Extracted Size", $"{payload.Value.Length:N0} bytes");
            }
        }
        catch (Exception ex)
        {
            Formatter.WriteError($"Failed to extract payload: {ex.Message}");
        }
    }

    private void DisplaySignatureInfo(CoseSign1Message message)
    {
        Formatter.WriteInfo("Signature:");
        var encoded = message.Encode();
        Formatter.WriteKeyValue("  Total Size", $"{encoded.Length:N0} bytes");

        // Try to extract certificate chain from unprotected headers (x5chain is label 33)
        var x5chainLabel = new CoseHeaderLabel(33);
        if (message.UnprotectedHeaders.ContainsKey(x5chainLabel))
        {
            Formatter.WriteInfo("  Certificate Chain found in unprotected headers");
        }

        // Check protected headers too
        if (message.ProtectedHeaders.ContainsKey(x5chainLabel))
        {
            Formatter.WriteInfo("  Certificate Chain found in protected headers");
        }
    }

    private static string GetAlgorithmName(int algorithm)
    {
        return algorithm switch
        {
            // ECDSA algorithms
            -7 => "ES256 (ECDSA w/ SHA-256)",
            -35 => "ES384 (ECDSA w/ SHA-384)",
            -36 => "ES512 (ECDSA w/ SHA-512)",
            // RSA-PSS algorithms
            -37 => "PS256 (RSASSA-PSS w/ SHA-256)",
            -38 => "PS384 (RSASSA-PSS w/ SHA-384)",
            -39 => "PS512 (RSASSA-PSS w/ SHA-512)",
            // RSA PKCS#1 algorithms
            -257 => "RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)",
            -258 => "RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)",
            -259 => "RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)",
            // Hash algorithms (for payload-hash-alg)
            -16 => "SHA-256",
            -43 => "SHA-384",
            -44 => "SHA-512",
            _ => "Unknown"
        };
    }

    private static string GetHashAlgorithmName(int algorithm)
    {
        return algorithm switch
        {
            -16 => "SHA-256",
            -43 => "SHA-384",
            -44 => "SHA-512",
            _ => $"Unknown ({algorithm})"
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
                    return $"{hashName}: {Convert.ToHexString(thumbprint)}";
                }
            }

            // Generic decoding for simple types
            return state switch
            {
                CborReaderState.TextString => reader.ReadTextString(),
                CborReaderState.UnsignedInteger => reader.ReadUInt64().ToString(),
                CborReaderState.NegativeInteger => reader.ReadInt64().ToString(),
                CborReaderState.ByteString => $"<{value.EncodedValue.Length} bytes>",
                _ => $"<{value.EncodedValue.Length} bytes>"
            };
        }
        catch
        {
            return $"<{value.EncodedValue.Length} bytes>";
        }
    }

    // Well-known COSE header labels (from RFC 9052, RFC 9054, and extensions)
    // Using constants from CoseSign1.Headers library where available
    private static readonly Dictionary<int, string> WellKnownHeaders = new()
    {
        // Standard COSE headers (RFC 9052)
        { 1, "alg (Algorithm)" },
        { 2, "crit (Critical)" },
        { 3, "content type" },
        { 4, "kid (Key ID)" },
        { 5, "IV" },
        { 6, "Partial IV" },
        { 7, "counter signature" },
        // CWT Claims header (RFC 9597) - label 15
        { 15, "CWT Claims" },
        // X.509 certificate headers
        { 33, "x5chain (Certificate Chain)" },
        { 34, "x5t (Certificate Thumbprint)" },
        { 35, "x5u (Certificate URL)" },
        // COSE Hash Envelope headers (RFC 9054)
        { 258, "payload-hash-alg (Hash Algorithm)" },
        { 259, "payload-preimage-content-type" },
        { 260, "payload-location" },
        // SCITT transparency headers
        { 393, "scitt-receipts" },
        { 394, "scitt-statement" },
    };

    private static string GetHeaderName(CoseHeaderLabel label)
    {
        // Check against well-known labels from CoseSign1.Headers constants
        if (label.Equals(CWTClaimsHeaderLabels.CWTClaims))
        {
            return "CWT Claims";
        }
        if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg))
        {
            return "payload-hash-alg (Hash Algorithm)";
        }
        if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType))
        {
            return "payload-preimage-content-type";
        }
        if (label.Equals(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation))
        {
            return "payload-location";
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
        return "Header (custom)";
    }

    private static string FormatHeaderValue(CoseHeaderValue value)
    {
        if (value.EncodedValue.Length < 50)
        {
            return $"<{value.EncodedValue.Length} bytes>";
        }
        return $"<{value.EncodedValue.Length} bytes> [{Convert.ToHexString(value.EncodedValue.Span.Slice(0, 20))}...]";
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