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
    public override async Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        try
        {
            // Get required parameters
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");

            // Get optional parameters
            string? outputPath = GetOptionalValue(configuration, "output");
            string? rootCertsPath = GetOptionalValue(configuration, "roots");
            bool allowUntrusted = !string.IsNullOrEmpty(GetOptionalValue(configuration, "allow-untrusted"));
            bool allowOutdated = !string.IsNullOrEmpty(GetOptionalValue(configuration, "allow-outdated"));
            string? commonName = GetOptionalValue(configuration, "common-name");

            // Validate common parameters
            PluginExitCode validationResult = ValidateCommonParameters(configuration, out int timeoutSeconds);
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
            validationResult = ValidateFilePaths(requiredFiles);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            // Verify the indirect signature
            using CancellationTokenSource combinedCts = CreateTimeoutCancellationToken(timeoutSeconds, cancellationToken);
            (PluginExitCode exitCode, object? result) = await VerifyIndirectSignature(
                payloadPath, 
                signaturePath, 
                rootCertsPath,
                allowUntrusted,
                allowOutdated,
                commonName,
                combinedCts.Token);

            // Write output if requested
            if (!string.IsNullOrEmpty(outputPath) && result != null)
            {
                object outputResult = new
                {
                    Operation = "IndirectVerify",
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    IsValid = exitCode == PluginExitCode.Success,
                    Result = result
                };
                await WriteJsonResult(outputPath, outputResult, cancellationToken);
            }

            return exitCode;
        }
        catch (Exception ex)
        {
            return HandleCommonException(ex, configuration, cancellationToken);
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
    /// <param name="cancellationToken">Cancellation token with timeout.</param>
    /// <returns>Tuple containing the exit code and optional result object for JSON output.</returns>
    private static async Task<(PluginExitCode exitCode, object? result)> VerifyIndirectSignature(
        string payloadPath,
        string signaturePath,
        string? rootCertsPath,
        bool allowUntrusted,
        bool allowOutdated,
        string? commonName,
        CancellationToken cancellationToken)
    {
        try
        {
            // Read signature file
            byte[] signatureBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            // Check if this is an indirect signature
            if (!message.IsIndirectSignature())
            {
                Console.Error.WriteLine("Error: The signature is not an indirect signature.");
                return (PluginExitCode.InvalidArgumentValue, null);
            }

            PrintOperationStatus("Verifying", payloadPath, signaturePath);

            // Read payload
            byte[] payload = await File.ReadAllBytesAsync(payloadPath, cancellationToken);

            // Verify the signature matches the payload
            bool signatureMatches;
            using (MemoryStream payloadStream = new MemoryStream(payload))
            {
                signatureMatches = message.SignatureMatches(payloadStream);
            }

            if (!signatureMatches)
            {
                Console.WriteLine("❌ Indirect signature verification FAILED: Payload hash does not match signature");
                object failureResult = new
                {
                    Operation = "IndirectVerify",
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    IsValid = false,
                    FailureReason = "Payload hash does not match signature",
                    VerificationTime = DateTime.UtcNow
                };
                return (PluginExitCode.IndirectSignatureVerificationFailure, failureResult);
            }

            // Perform certificate validation using CoseHandler
            List<X509Certificate2>? rootCerts = null;
            if (!string.IsNullOrEmpty(rootCertsPath))
            {
                rootCerts = LoadRootCertificates(rootCertsPath);
            }

            ValidationResult validationResult = await ValidateCertificateChain(message, payload, rootCerts, allowUntrusted, allowOutdated, commonName);

            bool isValid = signatureMatches && validationResult.Success;
            string status = isValid ? "✅ SUCCESS" : "❌ FAILED";
            
            Console.WriteLine($"{status}: Indirect signature verification completed");
            
            if (validationResult.Success)
            {
                Console.WriteLine("  - Payload hash matches signature");
                Console.WriteLine("  - Certificate chain validation passed");
                
                if (validationResult.CertificateChain?.Count > 0)
                {
                    X509Certificate2 signingCert = validationResult.CertificateChain.First();
                    Console.WriteLine($"  - Signed by: {signingCert.Subject}");
                    Console.WriteLine($"  - Certificate thumbprint: {signingCert.Thumbprint}");
                }
            }
            else
            {
                if (signatureMatches)
                {
                    Console.WriteLine("  - Payload hash matches signature");
                }
                
                if (validationResult.Errors?.Count > 0)
                {
                    Console.WriteLine("  - Certificate validation errors:");
                    foreach (CoseValidationError error in validationResult.Errors)
                    {
                        Console.WriteLine($"    • {error.ErrorCode}: {error.Message}");
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
                PayloadHashMatches = signatureMatches,
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
            Console.Error.WriteLine($"Error verifying indirect signature: {ex.Message}");
            return (PluginExitCode.UnknownError, null);
        }
    }

    /// <summary>
    /// Loads root certificates from a file.
    /// </summary>
    /// <param name="rootCertsPath">Path to the root certificates file.</param>
    /// <returns>List of root certificates.</returns>
    private static List<X509Certificate2> LoadRootCertificates(string rootCertsPath)
    {
        try
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import(rootCertsPath);
            return collection.Cast<X509Certificate2>().ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: Failed to load root certificates from {rootCertsPath}: {ex.Message}");
            return new List<X509Certificate2>();
        }
    }

    /// <summary>
    /// Validates the certificate chain of the COSE Sign1 message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="payloadBytes">The payload bytes for validation.</param>
    /// <param name="rootCerts">Optional root certificates for validation.</param>
    /// <param name="allowUntrusted">Whether to allow untrusted certificate chains.</param>
    /// <param name="allowOutdated">Whether to allow outdated certificates.</param>
    /// <param name="commonName">Expected common name in signing certificate.</param>
    /// <returns>Validation result.</returns>
    private static Task<ValidationResult> ValidateCertificateChain(
        CoseSign1Message message, 
        byte[] payloadBytes,
        List<X509Certificate2>? rootCerts, 
        bool allowUntrusted, 
        bool allowOutdated, 
        string? commonName)
    {
        try
        {
            // Create a memory stream for the signature
            using MemoryStream signatureStream = new MemoryStream(message.Encode());
            using MemoryStream payloadStream = new MemoryStream(payloadBytes);
            
            // Validate the signature with payload for certificate chain validation
            ValidationResult result = CoseHandler.Validate(
                signature: signatureStream,
                payload: payloadStream, // Provide payload for full validation
                roots: rootCerts,
                revocationMode: X509RevocationMode.NoCheck, // Default for indirect signatures
                requiredCommonName: commonName,
                allowUntrusted: allowUntrusted,
                allowOutdated: allowOutdated);

            return Task.FromResult(result);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Certificate validation error: {ex.Message}");
            ValidationResult result = new ValidationResult(false, null);
            result.AddError(ValidationFailureCode.Unknown);
            return Task.FromResult(result);
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
               $"  --common-name   Expected common name in the signing certificate{Environment.NewLine}";
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
               $"  # Verify with JSON output{Environment.NewLine}" +
               $"  CoseSignTool indirect-verify --payload myfile.txt --signature myfile.cose --output result.json{Environment.NewLine}";
    }
}
