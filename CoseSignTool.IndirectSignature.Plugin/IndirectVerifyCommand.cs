// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin;

/// <summary>
/// Command to verify an indirect COSE Sign1 signature.
/// </summary>
public class IndirectVerifyCommand : IndirectSignatureCommandBase
{
    /// <inheritdoc/>
    public override string Name => "indirect-verify";

    /// <inheritdoc/>
    public override string Description => "Verifies an indirect COSE Sign1 signature against a payload file";

    /// <inheritdoc/>
    public override IDictionary<string, string> Options
    {
        get
        {
            Dictionary<string, string> options = new Dictionary<string, string>(CommonOptions);
            foreach (KeyValuePair<string, string> option in ValidationOptions)
            {
                options[option.Key] = option.Value;
            }
            return options;
        }
    }

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage("indirect-verify", "verify") + 
                                   GetValidationUsage() + 
                                   GetAdditionalOptionalArguments() + 
                                   GetExamples();

    /// <inheritdoc/>
    public override IReadOnlyCollection<string> BooleanOptions => ValidationBooleanOptions;

    /// <inheritdoc/>
    public override async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        try
        {
            Logger.LogVerbose("Starting indirect verify operation");

            // Get required parameters
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");

            // Get optional parameters
            string? outputPath = GetOptionalValue(configuration, "output");
            string? rootCertsPath = GetOptionalValue(configuration, "roots");
            bool allowUntrusted = GetBooleanFlag(configuration, "allow-untrusted");
            bool allowOutdated = GetBooleanFlag(configuration, "allow-outdated");
            string? commonName = GetOptionalValue(configuration, "common-name");
            string? revocationModeString = GetOptionalValue(configuration, "revocation-mode");
            
            // Validate revocation mode before parsing
            if (!string.IsNullOrEmpty(revocationModeString) && 
                !Enum.TryParse<X509RevocationMode>(revocationModeString, ignoreCase: true, out _))
            {
                throw new ArgumentException($"Invalid revocation mode '{revocationModeString}'. Valid values are: {string.Join(", ", Enum.GetNames<X509RevocationMode>())}", nameof(revocationModeString));
            }
            
            X509RevocationMode revocationMode = ParseRevocationMode(revocationModeString, X509RevocationMode.NoCheck);

            // Validate common parameters
            PluginExitCode validationResult = ValidateCommonParameters(configuration, out int timeoutSeconds, Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Validate file paths
            Dictionary<string, string?> requiredFiles = new Dictionary<string, string?>
            {
                { "Payload", payloadPath },
                { "Signature", signaturePath }
            };

            if (!string.IsNullOrEmpty(rootCertsPath))
            {
                requiredFiles["Root certificates"] = rootCertsPath;
            }

            AddAdditionalFileValidation(requiredFiles, configuration);
            validationResult = ValidateFilePaths(requiredFiles, Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Verify the indirect signature
            using CancellationTokenSource combinedCts = CreateTimeoutCancellationToken(timeoutSeconds, cancellationToken);
            Logger.LogVerbose($"Verifying with revocation mode: {revocationMode}");
            if (!string.IsNullOrEmpty(commonName))
            {
                Logger.LogVerbose($"Expected common name: {commonName}");
            }
            (PluginExitCode exitCode, object? result) = await VerifyIndirectSignature(
                payloadPath, 
                signaturePath, 
                rootCertsPath,
                allowUntrusted,
                allowOutdated,
                commonName,
                revocationMode,
                Logger,
                combinedCts.Token);

            // Write output if requested
            if (!string.IsNullOrEmpty(outputPath) && result != null)
            {
                Logger.LogVerbose($"Writing result to: {outputPath}");
                object outputResult = new
                {
                    Operation = "IndirectVerify",
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    IsValid = exitCode == PluginExitCode.Success,
                    Result = result
                };
                await WriteJsonResult(outputPath, outputResult, cancellationToken, Logger);
            }

            Logger.LogVerbose("Indirect verify operation completed");
            return exitCode;
        }
        catch (Exception ex)
        {
            return HandleCommonException(ex, configuration, cancellationToken, Logger);
        }
    }

    /// <summary>
    /// Verifies an indirect signature against the specified payload.
    /// </summary>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="rootCertsPath">Path to root certificates file (optional).</param>
    /// <param name="allowUntrusted">Whether to allow untrusted certificate chains.</param>
    /// <param name="allowOutdated">Whether to allow outdated certificates.</param>
    /// <param name="commonName">Expected common name in signing certificate (optional).</param>
    /// <param name="revocationMode">Certificate revocation checking mode.</param>
    /// <param name="logger">Logger for diagnostic output.</param>
    /// <param name="cancellationToken">Cancellation token with timeout.</param>
    /// <returns>Tuple containing the exit code and optional result object for JSON output.</returns>
    private static async Task<(PluginExitCode exitCode, object? result)> VerifyIndirectSignature(
        string payloadPath,
        string signaturePath,
        string? rootCertsPath,
        bool allowUntrusted,
        bool allowOutdated,
        string? commonName,
        X509RevocationMode revocationMode,
        IPluginLogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Verifying indirect COSE Sign1 message...");
            logger.LogVerbose($"Payload: {payloadPath}");
            logger.LogVerbose($"Signature: {signaturePath}");

            // Read signature and payload files
            logger.LogVerbose("Reading signature file...");
            byte[] signatureBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            logger.LogVerbose($"Signature size: {signatureBytes.Length} bytes");

            logger.LogVerbose("Reading payload file...");
            byte[] payload = await File.ReadAllBytesAsync(payloadPath, cancellationToken);
            logger.LogVerbose($"Payload size: {payload.Length} bytes");

            // First check if this is an indirect signature before performing validation
            logger.LogVerbose("Decoding COSE Sign1 message...");
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            if (!message.IsIndirectSignature())
            {
                logger.LogError("The signature is not an indirect signature.");
                return (PluginExitCode.InvalidArgumentValue, null);
            }
            logger.LogVerbose("Confirmed indirect signature format");

            // Load root certificates if provided
            List<X509Certificate2>? rootCerts = null;
            if (!string.IsNullOrEmpty(rootCertsPath))
            {
                logger.LogVerbose($"Loading root certificates from: {rootCertsPath}");
                rootCerts = LoadRootCertificates(rootCertsPath, logger);
                logger.LogVerbose($"Loaded {rootCerts?.Count ?? 0} root certificate(s)");
            }

            // Use CoseHandler.Validate to perform comprehensive validation
            logger.LogVerbose("Performing validation...");
            ValidationResult validationResult = CoseHandler.Validate(
                signature: signatureBytes,
                payload: payload,
                roots: rootCerts,
                revocationMode: revocationMode,
                requiredCommonName: commonName,
                allowUntrusted: allowUntrusted,
                allowOutdated: allowOutdated);

            bool isValid = validationResult.Success;
            
            if (validationResult.Success)
            {
                logger.LogInformation("✅ SUCCESS: Indirect signature verification completed");
                logger.LogVerbose("  - Payload hash matches signature");
                logger.LogVerbose("  - Certificate chain validation passed");
                
                if (validationResult.CertificateChain?.Count > 0)
                {
                    X509Certificate2 signingCert = validationResult.CertificateChain.First();
                    logger.LogInformation($"  - Signed by: {signingCert.Subject}");
                    logger.LogVerbose($"  - Certificate thumbprint: {signingCert.Thumbprint}");
                }
            }
            else
            {
                logger.LogError("❌ FAILED: Indirect signature verification failed");
                if (validationResult.Errors?.Count > 0)
                {
                    logger.LogError("  - Validation errors:");
                    foreach (CoseValidationError error in validationResult.Errors)
                    {
                        logger.LogError($"    • {error.ErrorCode}: {error.Message}");
                    }
                }
            }

            // Create result object for JSON output
            object jsonResult = new
            {
                Operation = "IndirectVerify",
                PayloadPath = payloadPath,
                SignaturePath = signaturePath,
                IsValid = isValid,
                ContentValidationType = validationResult.ContentValidationType.ToString(),
                CertificateValidation = new
                {
                    Success = validationResult.Success,
                    Errors = validationResult.Errors?.Select(e => new { e.ErrorCode, e.Message }).ToList()
                },
                SigningCertificate = validationResult.CertificateChain?.FirstOrDefault()?.Subject,
                CertificateThumbprint = validationResult.CertificateChain?.FirstOrDefault()?.Thumbprint,
                VerificationTime = DateTime.UtcNow
            };

            PluginExitCode exitCode = isValid ? PluginExitCode.Success : PluginExitCode.IndirectSignatureVerificationFailure;
            return (exitCode, jsonResult);
        }
        catch (Exception ex)
        {
            logger.LogError($"Error verifying indirect signature: {ex.Message}");
            logger.LogException(ex);
            return (PluginExitCode.UnknownError, null);
        }
    }

    /// <summary>
    /// Loads root certificates from a file.
    /// </summary>
    /// <param name="rootCertsPath">Path to the root certificates file.</param>
    /// <param name="logger">Logger for diagnostic output.</param>
    /// <returns>List of root certificates.</returns>
    private static List<X509Certificate2> LoadRootCertificates(string rootCertsPath, IPluginLogger logger)
    {
        try
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import(rootCertsPath);
            return collection.Cast<X509Certificate2>().ToList();
        }
        catch (Exception ex)
        {
            logger.LogWarning($"Failed to load root certificates from {rootCertsPath}: {ex.Message}");
            logger.LogException(ex);
            return new List<X509Certificate2>();
        }
    }

    /// <summary>
    /// Gets the validation usage section for the command help.
    /// </summary>
    private static string GetValidationUsage()
    {
        return $"{Environment.NewLine}" +
               $"Validation options:{Environment.NewLine}" +
               $"  --roots         Path to a file containing root certificates for validation{Environment.NewLine}" +
               $"  --allow-untrusted Allow signatures from untrusted certificate chains{Environment.NewLine}" +
               $"  --allow-outdated Allow signatures from outdated certificates{Environment.NewLine}" +
               $"  --common-name   Expected common name in the signing certificate{Environment.NewLine}" +
               $"  --revocation-mode Certificate revocation checking mode (NoCheck, Online, Offline, default: NoCheck){Environment.NewLine}";
    }

    /// <inheritdoc/>
    protected override string GetExamples()
    {
        return $"{Environment.NewLine}" +
               $"Examples:{Environment.NewLine}" +
               $"  # Verify indirect signature{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Verify with custom root certificates{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --roots rootcerts.pem{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Verify allowing untrusted chains{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --allow-untrusted{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Verify with expected common name{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --common-name \"My Company\"{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Verify with online revocation checking{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --revocation-mode Online{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"  # Verify with JSON output{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --output result.json{Environment.NewLine}";
    }
}
