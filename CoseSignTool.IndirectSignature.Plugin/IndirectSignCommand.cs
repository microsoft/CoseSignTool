// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin;

using CoseSign1.Abstractions.Interfaces;
using System.Text;

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
            
            // Add CWT Claims options for SCITT compliance
            options["enable-scitt"] = "Enable SCITT compliance with automatic CWT claims (default: true)";
            options["cwt-issuer"] = "The CWT issuer (iss) claim. Defaults to DID:x509 identity from certificate";
            options["cwt-subject"] = "The CWT subject (sub) claim. Defaults to 'UnknownIntent'";
            options["cwt-audience"] = "The CWT audience (aud) claim (optional)";
            
            // Add payload location option for CoseHashEnvelope format
            options["payload-location"] = "A URI indicating where the payload can be retrieved from (optional, CoseHashEnvelope format only)";
            
            return options;
        }
    }

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage("indirect-sign", "sign") + 
                                   GetCertificateUsage() + 
                                   GetAdditionalOptionalArguments() + 
                                   GetCertificateProviderInfo() +
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

            // Parse CWT Claims parameters for SCITT compliance
            bool enableScitt = GetOptionalValue(configuration, "enable-scitt", "true") != "false";
            string? cwtIssuer = GetOptionalValue(configuration, "cwt-issuer");
            string? cwtSubject = GetOptionalValue(configuration, "cwt-subject");
            string? cwtAudience = GetOptionalValue(configuration, "cwt-audience");
            
            // Parse custom CWT claims (can be specified multiple times)
            List<string>? cwtClaims = null;
            string? cwtClaimsValue = GetOptionalValue(configuration, "cwt-claims");
            if (!string.IsNullOrWhiteSpace(cwtClaimsValue))
            {
                cwtClaims = new List<string> { cwtClaimsValue };
                // Check for additional claims with indexed keys
                int index = 1;
                while (true)
                {
                    string? additionalClaim = GetOptionalValue(configuration, $"cwt-claims:{index}");
                    if (string.IsNullOrWhiteSpace(additionalClaim))
                    {
                        break;
                    }
                    cwtClaims.Add(additionalClaim);
                    index++;
                }
            }
            
            Logger.LogVerbose($"SCITT compliance: {enableScitt}");
            if (!string.IsNullOrEmpty(cwtIssuer))
            {
                Logger.LogVerbose($"CWT Issuer: {cwtIssuer}");
            }
            if (!string.IsNullOrEmpty(cwtSubject))
            {
                Logger.LogVerbose($"CWT Subject: {cwtSubject}");
            }
            if (!string.IsNullOrEmpty(cwtAudience))
            {
                Logger.LogVerbose($"CWT Audience: {cwtAudience}");
            }
            if (cwtClaims != null && cwtClaims.Count > 0)
            {
                Logger.LogVerbose($"Custom CWT claims count: {cwtClaims.Count}");
            }

            // Parse payload location for CoseHashEnvelope format
            string? payloadLocation = GetOptionalValue(configuration, "payload-location");
            if (!string.IsNullOrEmpty(payloadLocation))
            {
                Logger.LogVerbose($"Payload location: {payloadLocation}");
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
                enableScitt,
                cwtIssuer,
                cwtSubject,
                cwtAudience,
                cwtClaims,
                payloadLocation,
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
    /// <param name="enableScitt">Whether to enable SCITT compliance with CWT claims.</param>
    /// <param name="cwtIssuer">Optional CWT issuer claim.</param>
    /// <param name="cwtSubject">Optional CWT subject claim.</param>
    /// <param name="cwtAudience">Optional CWT audience claim.</param>
    /// <param name="cwtClaims">Optional custom CWT claims as label:value pairs.</param>
    /// <param name="payloadLocation">Optional URI indicating where the payload can be retrieved from.</param>
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
        bool enableScitt,
        string? cwtIssuer,
        string? cwtSubject,
        string? cwtAudience,
        List<string>? cwtClaims,
        string? payloadLocation,
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
            X509Certificate2CoseSigningKeyProvider signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(
                signingCertificate: certificate,
                hashAlgorithm: hashAlgorithm,
                rootCertificates: additionalCertificates,
                enableScittCompliance: enableScitt);

            // Create header extender from configuration
            ICoseHeaderExtender? headerExtender = CoseHeaderHelper.CreateHeaderExtender(configuration);
            if (headerExtender != null)
            {
                logger.LogVerbose("Custom COSE headers will be applied");
            }

            // If CWT claims customization is requested, create a CWT extender
            // Note: When EnableScittCompliance is true, CertificateCoseSigningKeyProvider automatically adds default CWT claims
            // We only need to create a customizer if the user wants to override defaults
            if (!string.IsNullOrEmpty(cwtIssuer) || !string.IsNullOrEmpty(cwtSubject) || !string.IsNullOrEmpty(cwtAudience) || (cwtClaims != null && cwtClaims.Count > 0))
            {
                logger.LogVerbose("Creating CWT claims customizer to override defaults");
                
                // Create a CWT claims extender with user-specified values
                // This will merge with and override the automatic defaults from CertificateCoseSigningKeyProvider
                CoseSign1.Headers.CWTClaimsHeaderExtender cwtCustomizer = new();

                // Override issuer if specified
                if (!string.IsNullOrEmpty(cwtIssuer))
                {
                    logger.LogVerbose($"Overriding CWT issuer: {cwtIssuer}");
                    cwtCustomizer.SetIssuer(cwtIssuer);
                }

                // Override subject if specified
                if (!string.IsNullOrEmpty(cwtSubject))
                {
                    logger.LogVerbose($"Overriding CWT subject: {cwtSubject}");
                    cwtCustomizer.SetSubject(cwtSubject);
                }

                // Add audience if specified
                if (!string.IsNullOrEmpty(cwtAudience))
                {
                    logger.LogVerbose($"Setting CWT audience: {cwtAudience}");
                    cwtCustomizer.SetAudience(cwtAudience);
                }

                // Apply any custom CWT claims
                if (cwtClaims != null && cwtClaims.Count > 0)
                {
                    logger.LogVerbose($"Applying {cwtClaims.Count} custom CWT claims");
                    ApplyCwtClaims(cwtCustomizer, cwtClaims);
                }

                // Chain the CWT customizer with any existing header extender
                if (headerExtender != null)
                {
                    logger.LogVerbose("Chaining CWT claims with custom headers");
                    headerExtender = new CoseSign1.Headers.ChainedCoseHeaderExtender(new[] { cwtCustomizer, headerExtender });
                }
                else
                {
                    headerExtender = cwtCustomizer;
                }
            }

            // Create indirect signature factory
            using IndirectSignatureFactory factory = new IndirectSignatureFactory(hashAlgorithm);
            
            // Create the indirect signature with optional header extender
            // Note: When EnableScittCompliance is true, CertificateCoseSigningKeyProvider automatically includes default CWT claims
            logger.LogVerbose("Creating indirect signature...");
            // Use async method to support cancellation via the cancellationToken
            using MemoryStream payloadStream = new(payload);
            CoseSign1Message indirectSignature = await factory.CreateIndirectSignatureAsync(
                payload: payloadStream,
                signingKeyProvider: signingKeyProvider,
                contentType: contentType,
                signatureVersion: signatureVersion,
                coseHeaderExtender: headerExtender,
                cancellationToken: cancellationToken,
                payloadLocation: payloadLocation);

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
    /// Parses and applies custom CWT claims from a list of label:value strings to the CWTClaimsHeaderExtender.
    /// Supports both integer labels and RFC 8392 claim names.
    /// </summary>
    /// <param name="extender">The CWTClaimsHeaderExtender to apply claims to.</param>
    /// <param name="claimStrings">A list of "label:value" strings.</param>
    /// <exception cref="ArgumentException">Thrown when a claim string is invalid.</exception>
    private static void ApplyCwtClaims(CoseSign1.Headers.CWTClaimsHeaderExtender extender, List<string> claimStrings)
    {
        foreach (string claimString in claimStrings)
        {
            // Split by colon separator
            string[] parts = claimString.Split(':', 2);
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid CWT claim format: '{claimString}'. Expected format: 'label:value'");
            }

            string label = parts[0].Trim();
            string value = parts[1]; // Don't trim value - it might be intentional

            // Try to parse label as integer first
            if (int.TryParse(label, out int labelInt))
            {
                // Try to parse value as different types
                if (int.TryParse(value, out int valueInt))
                {
                    // Integer value
                    extender.SetCustomClaim(labelInt, valueInt);
                }
                else if (long.TryParse(value, out long valueLong))
                {
                    // Long value (for timestamps)
                    extender.SetCustomClaim(labelInt, valueLong);
                }
                else
                {
                    // String value
                    extender.SetCustomClaim(labelInt, value);
                }
            }
            else
            {
                // Label is a name, try to map to known claims
                switch (label.ToLowerInvariant())
                {
                    case "iss":
                    case "issuer":
                        extender.SetIssuer(value);
                        break;
                    case "sub":
                    case "subject":
                        extender.SetSubject(value);
                        break;
                    case "aud":
                    case "audience":
                        extender.SetAudience(value);
                        break;
                    case "exp":
                    case "expirationtime":
                        // Try parsing as DateTimeOffset first, then fall back to Unix timestamp
                        if (DateTimeOffset.TryParse(value, out DateTimeOffset expDate))
                        {
                            extender.SetExpirationTime(expDate);
                        }
                        else if (long.TryParse(value, out long exp))
                        {
                            extender.SetExpirationTime(exp);
                        }
                        else
                        {
                            throw new ArgumentException($"Invalid expiration time value: '{value}'. Expected a date/time string (e.g., '2024-12-31T23:59:59Z') or Unix timestamp (long integer).");
                        }
                        break;
                    case "nbf":
                    case "notbefore":
                        // Try parsing as DateTimeOffset first, then fall back to Unix timestamp
                        if (DateTimeOffset.TryParse(value, out DateTimeOffset nbfDate))
                        {
                            extender.SetNotBefore(nbfDate);
                        }
                        else if (long.TryParse(value, out long nbf))
                        {
                            extender.SetNotBefore(nbf);
                        }
                        else
                        {
                            throw new ArgumentException($"Invalid not-before value: '{value}'. Expected a date/time string (e.g., '2024-12-31T23:59:59Z') or Unix timestamp (long integer).");
                        }
                        break;
                    case "iat":
                    case "issuedAt":
                        // Try parsing as DateTimeOffset first, then fall back to Unix timestamp
                        if (DateTimeOffset.TryParse(value, out DateTimeOffset iatDate))
                        {
                            extender.SetIssuedAt(iatDate);
                        }
                        else if (long.TryParse(value, out long iat))
                        {
                            extender.SetIssuedAt(iat);
                        }
                        else
                        {
                            throw new ArgumentException($"Invalid issued-at value: '{value}'. Expected a date/time string (e.g., '2024-12-31T23:59:59Z') or Unix timestamp (long integer).");
                        }
                        break;
                    case "cti":
                    case "cwtid":
                        // Convert string to UTF-8 bytes for CWT ID
                        byte[] cwtIdBytes = System.Text.Encoding.UTF8.GetBytes(value);
                        extender.SetCWTID(cwtIdBytes);
                        break;
                    default:
                        throw new ArgumentException($"Unknown CWT claim name: '{label}'. Use an integer label or one of: iss, sub, aud, exp, nbf, iat, cti.");
                }
            }
        }
    }

    /// <summary>
    /// Gets the certificate usage section for the command help.
    /// </summary>
    private static string GetCertificateUsage()
    {
        StringBuilder usage = new StringBuilder();
        usage.AppendLine();
        usage.AppendLine("Certificate options (one source required for signing):");
        usage.AppendLine();
        
        // Add certificate provider options if any are available
        usage.AppendLine("  Certificate Provider Plugin (recommended for cloud/HSM signing):");
        usage.AppendLine("    --cert-provider   Use a certificate provider plugin (e.g., azure-trusted-signing)");
        usage.AppendLine("                      See Certificate Providers section below for available providers");
        usage.AppendLine();
        usage.AppendLine("  --OR--");
        usage.AppendLine();
        usage.AppendLine("  Local PFX Certificate:");
        usage.AppendLine("    --pfx             Path to a private key certificate file (.pfx) to sign with");
        usage.AppendLine("    --password        The password for the .pfx file if it has one");
        usage.AppendLine();
        usage.AppendLine("  --OR--");
        usage.AppendLine();
        usage.AppendLine("  Local Certificate Store:");
        usage.AppendLine("    --thumbprint      The SHA1 thumbprint of a certificate in the local certificate store");
        usage.AppendLine("    --store-name      The name of the local certificate store (default: My)");
        usage.AppendLine("    --store-location  The location of the local certificate store (default: CurrentUser)");
        usage.AppendLine();
        usage.AppendLine("SCITT compliance options:");
        usage.AppendLine("  --enable-scitt    Enable SCITT compliance with CWT claims (default: true)");
        usage.AppendLine("  --cwt-issuer      CWT issuer claim. Defaults to DID:x509 from certificate");
        usage.AppendLine("  --cwt-subject     CWT subject claim. Defaults to 'unknown.intent'");
        usage.AppendLine("  --cwt-audience    CWT audience claim (optional)");
        usage.AppendLine("  --cwt-claims      Custom CWT claims as label:value pairs. Can be specified multiple times.");
        usage.AppendLine("                    Labels: integers or RFC 8392 names (iss, sub, aud, exp, nbf, iat, cti).");
        usage.AppendLine("                    Timestamps accept date/time strings or Unix timestamps.");
        usage.AppendLine("                    Examples: --cwt-claims \"exp:2024-12-31T23:59:59Z\" --cwt-claims \"100:custom-value\"");
        
        return usage.ToString();
    }

    /// <summary>
    /// Gets certificate provider information for help display.
    /// </summary>
    private static string GetCertificateProviderInfo()
    {
        // Try to access the certificate provider manager via reflection
        // since we're in a plugin and don't have direct static access
        Type? coseSignToolType = Type.GetType("CoseSignTool.CoseSignTool, CoseSignTool");
        if (coseSignToolType == null)
        {
            return string.Empty;
        }

        System.Reflection.FieldInfo? managerField = coseSignToolType.GetField(
            "CertificateProviderManager",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public);
        
        if (managerField == null)
        {
            return string.Empty;
        }

        object? managerObj = managerField.GetValue(null);
        if (managerObj is not CertificateProviderPluginManager manager || manager.Providers.Count == 0)
        {
            return string.Empty;
        }

        // Build a simple provider list with reference to detailed help
        StringBuilder sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine("  The following certificate provider plugins are available:");
        sb.AppendLine();
        
        foreach (var kvp in manager.Providers)
        {
            sb.AppendLine($"  {kvp.Key,-30} {kvp.Value.Description}");
            
            // Show required parameters if available
            var providerOptions = kvp.Value.GetProviderOptions();
            if (providerOptions.Any())
            {
                sb.AppendLine($"    Usage: CoseSignTool indirect-sign --payload <file> --signature <file> --cert-provider {kvp.Key} [options]");
                sb.AppendLine($"    Options:");
                foreach (var optionKey in providerOptions.Keys.Where(k => k.StartsWith("--")).Distinct())
                {
                    sb.AppendLine($"      {optionKey}");
                }
            }
            sb.AppendLine();
        }
        
        sb.AppendLine("  For detailed documentation, use: CoseSignTool help <provider-name>");
        sb.AppendLine();
        
        return sb.ToString();
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
