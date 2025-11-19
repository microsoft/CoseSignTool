// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin;

using CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Command to create an indirect COSE Sign1 signature.
/// </summary>
public class IndirectSignCommand : IndirectSignatureCommandBase
{
    /// <inheritdoc/>
    public override string Name => "indirect-sign";

    /// <inheritdoc/>
    public override string Description => "Creates an indirect COSE Sign1 signature for a payload file";

    /// <inheritdoc/>
    public override IDictionary<string, string> Options
    {
        get
        {
            Dictionary<string, string> options = new Dictionary<string, string>(CommonOptions);
            foreach (KeyValuePair<string, string> option in CertificateOptions)
            {
                options[option.Key] = option.Value;
            }
            foreach (KeyValuePair<string, string> option in HeaderOptions)
            {
                options[option.Key] = option.Value;
            }
            return options;
        }
    }

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage("indirect-sign", "sign") + 
                                   GetCertificateUsage() + 
                                   GetAdditionalOptionalArguments() + 
                                   GetExamples();

    /// <inheritdoc/>
    public override async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        try
        {
            Logger.LogVerbose("Starting indirect sign operation");

            // Get required parameters
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");

            // Get optional parameters
            string? outputPath = GetOptionalValue(configuration, "output");
            string contentType = GetOptionalValue(configuration, "content-type", "application/octet-stream") ?? "application/octet-stream";

            // Validate common parameters
            PluginExitCode validationResult = ValidateCommonParameters(configuration, out int timeoutSeconds, Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Validate file paths
            Dictionary<string, string?> requiredFiles = new Dictionary<string, string?>
            {
                { "Payload", payloadPath }
            };

            AddAdditionalFileValidation(requiredFiles, configuration);
            validationResult = ValidateFilePaths(requiredFiles, Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Load signing certificate
            (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode certResult) = LoadSigningCertificate(configuration, Logger);
            if (certResult != PluginExitCode.Success || certificate == null)
            {
                return certResult;
            }

            // Parse algorithm and version parameters
            HashAlgorithmName hashAlgorithm;
            IndirectSignatureFactory.IndirectSignatureVersion signatureVersion;
            
            try
            {
                hashAlgorithm = ParseHashAlgorithm(configuration);
                signatureVersion = ParseSignatureVersion(configuration);
            }
            catch (ArgumentException ex)
            {
                Logger?.LogError(ex.Message);
                return PluginExitCode.InvalidArgumentValue;
            }

            // Create the indirect signature
            using CancellationTokenSource combinedCts = CreateTimeoutCancellationToken(timeoutSeconds, cancellationToken);
            Logger.LogVerbose($"Creating indirect signature with hash algorithm: {hashAlgorithm.Name}, version: {signatureVersion}");
            (PluginExitCode exitCode, JsonElement? result) = await CreateIndirectSignature(
                payloadPath, 
                signaturePath, 
                certificate, 
                additionalCertificates,
                contentType, 
                hashAlgorithm, 
                signatureVersion,
                configuration,
                Logger,
                combinedCts.Token);

            // Write output if requested
            if (!string.IsNullOrEmpty(outputPath) && result.HasValue)
            {
                Logger.LogVerbose($"Writing result to: {outputPath}");
                object outputResult = new
                {
                    Operation = "IndirectSign",
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    Success = exitCode == PluginExitCode.Success,
                    Result = result.Value
                };
                await WriteJsonResult(outputPath, outputResult, cancellationToken, Logger);
            }

            Logger.LogVerbose("Indirect sign operation completed");
            return exitCode;
        }
        catch (Exception ex)
        {
            return HandleCommonException(ex, configuration, cancellationToken, Logger);
        }
    }

    /// <summary>
    /// Creates an indirect signature for the specified payload.
    /// </summary>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path where the signature will be written.</param>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="additionalCertificates">Additional certificates to include in the signature.</param>
    /// <param name="contentType">The content type of the payload.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="signatureVersion">The indirect signature version to create.</param>
    /// <param name="configuration">The configuration containing header options.</param>
    /// <param name="logger">Logger for diagnostic output.</param>
    /// <param name="cancellationToken">Cancellation token with timeout.</param>
    /// <returns>Tuple containing the exit code and optional result object for JSON output.</returns>
    private static async Task<(PluginExitCode exitCode, JsonElement? result)> CreateIndirectSignature(
        string payloadPath,
        string signaturePath,
        X509Certificate2 certificate,
        List<X509Certificate2>? additionalCertificates,
        string contentType,
        HashAlgorithmName hashAlgorithm,
        IndirectSignatureFactory.IndirectSignatureVersion signatureVersion,
        IConfiguration configuration,
        IPluginLogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            // Read payload
            logger.LogVerbose($"Reading payload from: {payloadPath}");
            byte[] payload = await File.ReadAllBytesAsync(payloadPath, cancellationToken);
            logger.LogVerbose($"Payload size: {payload.Length} bytes");
            
            // Create signing key provider
            logger.LogVerbose($"Using certificate: {certificate.Subject}");
            logger.LogVerbose($"Certificate thumbprint: {certificate.Thumbprint}");
            X509Certificate2CoseSigningKeyProvider signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(certificate);

            // Create header extender from configuration
            ICoseHeaderExtender? headerExtender = CoseHeaderHelper.CreateHeaderExtender(configuration);
            if (headerExtender != null)
            {
                logger.LogVerbose("Custom COSE headers will be applied");
            }

            // Create indirect signature factory
            using IndirectSignatureFactory factory = new IndirectSignatureFactory(hashAlgorithm);
            
            // Create the indirect signature with optional header extender
            logger.LogVerbose("Creating indirect signature...");
            CoseSign1Message indirectSignature = factory.CreateIndirectSignature(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion: signatureVersion,
                coseHeaderExtender: headerExtender);

            // Encode and write signature to file
            byte[] signatureBytes = indirectSignature.Encode();
            logger.LogVerbose($"Encoded signature size: {signatureBytes.Length} bytes");
            await File.WriteAllBytesAsync(signaturePath, signatureBytes, cancellationToken);
            logger.LogVerbose($"Signature written to: {signaturePath}");

            logger.LogInformation($"Indirect signature created successfully ({signatureBytes.Length} bytes)");

            // Create result object for JSON output
            object jsonResult = new
            {
                Operation = "IndirectSign",
                PayloadPath = payloadPath,
                SignaturePath = signaturePath,
                ContentType = contentType,
                HashAlgorithm = hashAlgorithm.Name,
                SignatureVersion = signatureVersion.ToString(),
                SignatureSize = signatureBytes.Length,
                CertificateThumbprint = certificate.Thumbprint,
                HasCustomHeaders = headerExtender != null,
                CreationTime = DateTime.UtcNow
            };

            // Convert to JsonElement
            JsonElement jsonElement = JsonSerializer.SerializeToElement(jsonResult);

            return (PluginExitCode.Success, jsonElement);
        }
        catch (Exception ex)
        {
            logger.LogError($"Error creating indirect signature: {ex.Message}");
            logger.LogException(ex);
            return (PluginExitCode.UnknownError, null);
        }
    }

    /// <summary>
    /// Gets the certificate usage section for the command help.
    /// </summary>
    private static string GetCertificateUsage()
    {
        return $"{Environment.NewLine}" +
               $"Certificate options (one required for signing):{Environment.NewLine}" +
               $"  --pfx           Path to a private key certificate file (.pfx) to sign with{Environment.NewLine}" +
               $"  --password      The password for the .pfx file if it has one{Environment.NewLine}" +
               $"  --thumbprint    The SHA1 thumbprint of a certificate in the local certificate store{Environment.NewLine}" +
               $"  --store-name    The name of the local certificate store (default: My){Environment.NewLine}" +
               $"  --store-location The location of the local certificate store (default: CurrentUser){Environment.NewLine}";
    }

    /// <inheritdoc/>
    protected override string GetExamples()
    {
        return $"{Environment.NewLine}" +
               $"Examples:{Environment.NewLine}" +
               $"  # Create indirect signature using PFX certificate{Environment.NewLine}" +
               $"  CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Create indirect signature using certificate store{Environment.NewLine}" +
               $"  CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --thumbprint ABC123...{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Create indirect signature with custom content type and hash algorithm{Environment.NewLine}" +
               $"  CoseSignTool indirect-sign --payload myfile.json --signature myfile.cose --pfx mycert.pfx --content-type application/json --hash-algorithm SHA384{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Create indirect signature with JSON output{Environment.NewLine}" +
               $"  CoseSignTool indirect-sign --payload myfile.txt --signature myfile.cose --pfx mycert.pfx --output result.json{Environment.NewLine}";
    }
}
