// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine.Invocation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSignTool.Output;

namespace CoseSignTool.Commands.Handlers;

/// <summary>
/// Handles the 'sign' command for creating COSE Sign1 signatures with ephemeral test certificates.
/// For production signing, use plugin commands: sign-pfx, sign-certstore, or sign-azure.
/// </summary>
public class SignCommandHandler
{
    private readonly IOutputFormatter _formatter;

    /// <summary>
    /// Initializes a new instance of the <see cref="SignCommandHandler"/> class.
    /// </summary>
    /// <param name="formatter">The output formatter to use (defaults to TextOutputFormatter).</param>
    public SignCommandHandler(IOutputFormatter? formatter = null)
    {
        _formatter = formatter ?? new TextOutputFormatter();
    }

    /// <summary>
    /// Handles the sign command asynchronously.
    /// </summary>
    /// <param name="context">The invocation context containing command arguments and options.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public Task<int> HandleAsync(InvocationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            // Get bound values from the parse result
            var parseResult = context.ParseResult;
            var commandResult = parseResult.CommandResult;
            
            // Find the payload argument
            FileInfo? payload = null;
            foreach (var arg in commandResult.Command.Arguments)
            {
                if (arg.Name == "payload")
                {
                    payload = parseResult.GetValueForArgument(arg) as FileInfo;
                    break;
                }
            }
            
            if (payload == null || !payload.Exists)
            {
                _formatter.WriteError($"Payload file not found: {payload?.FullName ?? "null"}");
                return Task.FromResult((int)ExitCode.FileNotFound);
            }

            // Find options
            FileInfo? output = null;
            bool detached = false;
            
            foreach (var option in commandResult.Command.Options)
            {
                var optionName = option.Name;
                if (optionName == "output")
                {
                    output = parseResult.GetValueForOption(option) as FileInfo;
                }
                else if (optionName == "detached")
                {
                    var value = parseResult.GetValueForOption(option);
                    detached = value is bool b && b;
                }
            }

            // Determine output path
            var outputPath = output?.FullName ?? $"{payload.FullName}.cose";

            _formatter.BeginSection("Signing Operation (Ephemeral Test Certificate)");
            _formatter.WriteKeyValue("Payload", payload.FullName);
            _formatter.WriteKeyValue("Output", outputPath);
            _formatter.WriteKeyValue("Mode", detached ? "Detached" : "Embedded");
            _formatter.WriteKeyValue("Certificate Source", "Ephemeral test certificate (NOT FOR PRODUCTION)");

            // Read payload
            var payloadBytes = File.ReadAllBytes(payload.FullName);

            // Create ephemeral test certificate
            using var testCert = CreateTestSigningCertificate();
            using var signingService = new LocalCertificateSigningService(testCert, new[] { testCert });
            using var factory = new DirectSignatureFactory(signingService);

            var options = new DirectSignatureOptions { EmbedPayload = !detached };
            var signatureBytes = factory.CreateCoseSign1MessageBytes(payloadBytes, "application/octet-stream", options);

            File.WriteAllBytes(outputPath, signatureBytes);
            
            _formatter.WriteSuccess("Successfully signed payload with test certificate");
            _formatter.WriteKeyValue("Signature Size", $"{signatureBytes.Length:N0} bytes");
            _formatter.WriteWarning("⚠ WARNING: Ephemeral test certificate used. Not suitable for production!");
            _formatter.WriteInfo("For production signing, use: sign-pfx, sign-certstore, or sign-azure");
            _formatter.EndSection();
            
            return Task.FromResult((int)ExitCode.Success);
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _formatter.WriteError($"Error signing payload: {ex.Message}");
            return Task.FromResult((int)ExitCode.SigningFailed);
        }
    }

    /// <summary>
    /// Creates a test signing certificate for demonstration purposes.
    /// In production, this would load from certificate store or configuration.
    /// </summary>
    private static X509Certificate2 CreateTestSigningCertificate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=CoseSignTool Test Certificate",
            ecdsa,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        return cert;
    }
}
