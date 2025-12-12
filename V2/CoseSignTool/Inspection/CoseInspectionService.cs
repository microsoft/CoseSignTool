// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
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
    /// <returns>Exit code indicating success or failure.</returns>
    public async Task<int> InspectAsync(string filePath)
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

            Formatter.BeginSection("COSE Sign1 Signature Details");
            Formatter.WriteKeyValue("File", fileInfo.FullName);
            Formatter.WriteKeyValue("Size", $"{fileInfo.Length:N0} bytes");

            // Try to decode as COSE Sign1
            try
            {
                var message = CoseSign1Message.DecodeSign1(bytes);

                // Display protected headers
                DisplayProtectedHeaders(message);

                // Display unprotected headers
                DisplayUnprotectedHeaders(message);

                // Display payload information
                DisplayPayloadInfo(message);

                // Display signature information
                DisplaySignatureInfo(message);

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
            Formatter.WriteKeyValue($"  {headerName}", $"<{header.Value.EncodedValue.Length} bytes>");
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
            -7 => "ES256 (ECDSA w/ SHA-256)",
            -35 => "ES384 (ECDSA w/ SHA-384)",
            -36 => "ES512 (ECDSA w/ SHA-512)",
            -37 => "PS256 (RSASSA-PSS w/ SHA-256)",
            -38 => "PS384 (RSASSA-PSS w/ SHA-384)",
            -39 => "PS512 (RSASSA-PSS w/ SHA-512)",
            -257 => "RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)",
            -258 => "RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)",
            -259 => "RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)",
            _ => "Unknown"
        };
    }

    private static string GetHeaderName(CoseHeaderLabel label)
    {
        // CoseHeaderLabel is a struct that can be created from int or string
        // We need to determine which one it is
        try
        {
            // Try to get the int value
            var value = label.GetHashCode(); // This is a workaround - need to inspect the actual structure
            return value switch
            {
                1 => "alg (Algorithm)",
                2 => "crit (Critical)",
                3 => "content type",
                4 => "kid (Key ID)",
                5 => "IV",
                6 => "Partial IV",
                7 => "counter signature",
                33 => "x5chain (Certificate Chain)",
                34 => "x5t (Certificate Thumbprint)",
                35 => "x5u (Certificate URL)",
                _ => $"Header {label}"
            };
        }
        catch
        {
            return $"Header {label}";
        }
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