// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin;

using CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Base class for indirect signature commands that provides common functionality
/// for parameter validation, certificate loading, file operations, error handling, and result output.
/// </summary>
public abstract class IndirectSignatureCommandBase : PluginCommandBase
{
    /// <summary>
    /// Common command options shared across all indirect signature commands.
    /// </summary>
    protected static readonly Dictionary<string, string> CommonOptions = new()
    {
        { "payload", "The file path to the payload file" },
        { "signature", "The file path where the COSE Sign1 signature file will be written or read from" },
        { "output", "The file path where the result will be written (optional)" },
        { "timeout", "Timeout in seconds for the operation (default: 30)" },
        { "content-type", "The content type of the payload (default: application/octet-stream)" },
        { "hash-algorithm", "The hash algorithm to use (SHA256, SHA384, SHA512, default: SHA256)" },
        { "signature-version", "The indirect signature version (CoseHashEnvelope, default: CoseHashEnvelope)" }
    };

    /// <summary>
    /// Certificate-related command options.
    /// </summary>
    protected static readonly Dictionary<string, string> CertificateOptions = new()
    {
        { "pfx", "A path to a private key certificate file (.pfx) to sign with" },
        { "password", "The password for the .pfx file if it has one" },
        { "thumbprint", "The SHA1 thumbprint of a certificate in the local certificate store" },
        { "store-name", "The name of the local certificate store (default: My)" },
        { "store-location", "The location of the local certificate store (default: CurrentUser)" },
        { "cert-provider", "The name of the certificate provider plugin to use (optional)" }
    };

    /// <summary>
    /// Validation options for verification commands.
    /// </summary>
    protected static readonly Dictionary<string, string> ValidationOptions = new()
    {
        { "roots", "Path to a file containing root certificates for validation" },
        { "allow-untrusted", "Allow signatures from untrusted certificate chains" },
        { "allow-outdated", "Allow signatures from outdated certificates" },
        { "common-name", "Expected common name in the signing certificate" },
        { "revocation-mode", "Certificate revocation checking mode (NoCheck, Online, Offline, default: NoCheck)" }
    };

    /// <summary>
    /// Boolean options that can be specified without an explicit value.
    /// These are common to verification commands.
    /// </summary>
    protected static readonly string[] ValidationBooleanOptions = new[]
    {
        "allow-untrusted",
        "allow-outdated"
    };

    /// <summary>
    /// Boolean options for signing commands (SCITT-related flags).
    /// </summary>
    protected static readonly string[] SigningBooleanOptions = new[]
    {
        "enable-scitt",
        "scitt"
    };

    /// <summary>
    /// Header options for customizing COSE headers.
    /// </summary>
    protected static readonly Dictionary<string, string> HeaderOptions = CoseHeaderHelper.HeaderOptions;

    /// <summary>
    /// Validates common parameters and returns parsed timeout value.
    /// </summary>
    /// <param name="configuration">The configuration containing command arguments.</param>
    /// <param name="timeoutSeconds">The parsed timeout value in seconds.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected internal static PluginExitCode ValidateCommonParameters(IConfiguration configuration, out int timeoutSeconds, IPluginLogger? logger = null)
    {
        string timeoutString = GetOptionalValue(configuration, "timeout", "30") ?? "30";
        
        if (!int.TryParse(timeoutString, out timeoutSeconds) || timeoutSeconds <= 0)
        {
            logger?.LogError("Invalid timeout value. Must be a positive integer.");
            return PluginExitCode.InvalidArgumentValue;
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Validates that required file paths exist.
    /// </summary>
    /// <param name="requiredFiles">Dictionary of file descriptions to file paths.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected internal static PluginExitCode ValidateFilePaths(Dictionary<string, string?> requiredFiles, IPluginLogger? logger = null)
    {
        foreach (KeyValuePair<string, string?> kvp in requiredFiles)
        {
            if (string.IsNullOrWhiteSpace(kvp.Value))
            {
                logger?.LogError($"{kvp.Key} file path is required.");
                return PluginExitCode.MissingRequiredOption;
            }

            if (!File.Exists(kvp.Value))
            {
                logger?.LogError($"{kvp.Key} file not found: {kvp.Value}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Loads a certificate for signing operations.
    /// </summary>
    /// <param name="configuration">The configuration containing certificate parameters.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>A tuple containing the certificate and any additional certificates, or null on failure.</returns>
    protected internal static (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) LoadSigningCertificate(IConfiguration configuration, IPluginLogger? logger = null)
    {
        // Check if a certificate provider is specified
        string? certProvider = GetOptionalValue(configuration, "cert-provider");
        if (!string.IsNullOrWhiteSpace(certProvider))
        {
            logger?.LogWarning("Certificate provider plugins are specified but not yet supported in indirect signature commands. " +
                             "Use --pfx or --thumbprint for certificate-based signing.");
            return (null, null, PluginExitCode.InvalidArgumentValue);
        }

        return LoadSigningCertificateFromLocal(configuration, logger);
    }

    /// <summary>
    /// Loads a signing key provider from either a certificate provider plugin or local certificate.
    /// </summary>
    /// <param name="configuration">The configuration containing certificate/provider parameters.</param>
    /// <param name="pluginManager">Optional certificate provider plugin manager for loading plugins.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>A tuple containing the key provider and exit code.</returns>
    protected internal static (ICoseSigningKeyProvider? keyProvider, PluginExitCode result) LoadSigningKeyProvider(
        IConfiguration configuration,
        CertificateProviderPluginManager? pluginManager = null,
        IPluginLogger? logger = null)
    {
        try
        {
            // Check if a certificate provider is specified
            string? certProvider = GetOptionalValue(configuration, "cert-provider");
            
            if (!string.IsNullOrWhiteSpace(certProvider))
            {
                // Use certificate provider plugin
                if (pluginManager == null)
                {
                    logger?.LogError($"Certificate provider '{certProvider}' was specified, but no certificate provider plugins are available.");
                    return (null, PluginExitCode.InvalidArgumentValue);
                }

                ICertificateProviderPlugin? plugin = pluginManager.GetProvider(certProvider);
                if (plugin == null)
                {
                    string availableProviders = pluginManager.Providers.Count > 0
                        ? string.Join(", ", pluginManager.Providers.Keys)
                        : "none";
                    logger?.LogError($"Certificate provider '{certProvider}' not found. Available providers: {availableProviders}");
                    return (null, PluginExitCode.InvalidArgumentValue);
                }

                if (!plugin.CanCreateProvider(configuration))
                {
                    logger?.LogError($"Certificate provider '{certProvider}' cannot create a provider with the given configuration. Required parameters may be missing.");
                    return (null, PluginExitCode.MissingRequiredOption);
                }

                ICoseSigningKeyProvider keyProvider = plugin.CreateProvider(configuration, logger);
                return (keyProvider, PluginExitCode.Success);
            }
            else
            {
                // Use local certificate (legacy behavior)
                (X509Certificate2? cert, List<X509Certificate2>? additionalCerts, PluginExitCode result) = 
                    LoadSigningCertificateFromLocal(configuration, logger);
                
                if (result != PluginExitCode.Success || cert == null)
                {
                    return (null, result);
                }

                ICoseSigningKeyProvider keyProvider = new CoseSign1.Certificates.Local.X509Certificate2CoseSigningKeyProvider(
                    null, cert, additionalCerts);
                return (keyProvider, PluginExitCode.Success);
            }
        }
        catch (ArgumentException ex)
        {
            logger?.LogError($"Invalid argument: {ex.Message}");
            logger?.LogException(ex);
            return (null, PluginExitCode.InvalidArgumentValue);
        }
        catch (InvalidOperationException ex)
        {
            logger?.LogError($"Operation failed: {ex.Message}");
            logger?.LogException(ex);
            return (null, PluginExitCode.CertificateLoadFailure);
        }
        catch (Exception ex)
        {
            logger?.LogError($"Unexpected error loading signing key provider: {ex.Message}");
            logger?.LogException(ex);
            return (null, PluginExitCode.UnknownError);
        }
    }

    /// <summary>
    /// Loads a certificate from local sources (PFX file or certificate store).
    /// </summary>
    /// <param name="configuration">The configuration containing certificate parameters.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>A tuple containing the certificate, additional certificates, and exit code.</returns>
    private static (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) LoadSigningCertificateFromLocal(IConfiguration configuration, IPluginLogger? logger = null)
    {
        try
        {
            string? pfxPath = GetOptionalValue(configuration, "pfx");
            string? password = GetOptionalValue(configuration, "password");
            string? thumbprint = GetOptionalValue(configuration, "thumbprint");
            string storeName = GetOptionalValue(configuration, "store-name", "My") ?? "My";
            string storeLocation = GetOptionalValue(configuration, "store-location", "CurrentUser") ?? "CurrentUser";

            if (!string.IsNullOrEmpty(pfxPath))
            {
                if (!File.Exists(pfxPath))
                {
                    logger?.LogError($"Certificate file not found: {pfxPath}");
                    return (null, null, PluginExitCode.UserSpecifiedFileNotFound);
                }

                X509Certificate2Collection collection = new X509Certificate2Collection();
                collection.Import(pfxPath, password, X509KeyStorageFlags.Exportable);

                if (collection.Count == 0)
                {
                    logger?.LogError("No certificates found in PFX file.");
                    return (null, null, PluginExitCode.CertificateLoadFailure);
                }

                // Find the certificate with a private key
                X509Certificate2? signingCert = null;
                List<X509Certificate2> additionalCerts = new();

                foreach (X509Certificate2 cert in collection)
                {
                    if (cert.HasPrivateKey && signingCert == null)
                    {
                        signingCert = cert;
                    }
                    else
                    {
                        additionalCerts.Add(cert);
                    }
                }

                if (signingCert == null)
                {
                    logger?.LogError("No certificate with private key found in PFX file.");
                    return (null, null, PluginExitCode.CertificateLoadFailure);
                }

                return (signingCert, additionalCerts.Count > 0 ? additionalCerts : null, PluginExitCode.Success);
            }
            else if (!string.IsNullOrEmpty(thumbprint))
            {
                if (!Enum.TryParse<StoreLocation>(storeLocation, true, out StoreLocation storeLocationEnum))
                {
                    logger?.LogError($"Invalid store location: {storeLocation}");
                    return (null, null, PluginExitCode.InvalidArgumentValue);
                }

                using X509Store store = new X509Store(storeName, storeLocationEnum);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection collection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (collection.Count == 0)
                {
                    logger?.LogError($"Certificate with thumbprint {thumbprint} not found in store {storeName}/{storeLocation}");
                    return (null, null, PluginExitCode.UserSpecifiedFileNotFound);
                }

                X509Certificate2 cert = collection[0];
                if (!cert.HasPrivateKey)
                {
                    logger?.LogError("Certificate does not have a private key.");
                    return (null, null, PluginExitCode.CertificateLoadFailure);
                }

                return (cert, null, PluginExitCode.Success);
            }
            else
            {
                logger?.LogError("Either --pfx or --thumbprint must be specified for signing operations.");
                return (null, null, PluginExitCode.MissingRequiredOption);
            }
        }
        catch (Exception ex)
        {
            logger?.LogError($"Error loading certificate: {ex.Message}");
            logger?.LogException(ex);
            return (null, null, PluginExitCode.CertificateLoadFailure);
        }
    }

    /// <summary>
    /// Parses the hash algorithm from configuration.
    /// </summary>
    /// <param name="configuration">The configuration containing the hash algorithm.</param>
    /// <returns>The parsed hash algorithm name.</returns>
    protected internal static HashAlgorithmName ParseHashAlgorithm(IConfiguration configuration)
    {
        string hashAlgorithm = GetOptionalValue(configuration, "hash-algorithm", "SHA256") ?? "SHA256";
        
        return hashAlgorithm.ToUpperInvariant() switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}")
        };
    }

    /// <summary>
    /// Parses the signature version from configuration.
    /// </summary>
    /// <param name="configuration">The configuration containing the signature version.</param>
    /// <returns>The parsed signature version.</returns>
    protected internal static IndirectSignatureFactory.IndirectSignatureVersion ParseSignatureVersion(IConfiguration configuration)
    {
        string version = GetOptionalValue(configuration, "signature-version", "CoseHashEnvelope") ?? "CoseHashEnvelope";
        
        return version switch
        {
            "CoseHashEnvelope" => IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope,
#pragma warning disable CS0618 // Type or member is obsolete
            "CoseHashV" => IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV,
            "Direct" => IndirectSignatureFactory.IndirectSignatureVersion.Direct,
#pragma warning restore CS0618 // Type or member is obsolete
            _ => throw new ArgumentException($"Unsupported signature version: {version}")
        };
    }

    /// <summary>
    /// Creates a cancellation token with timeout.
    /// </summary>
    /// <param name="timeoutSeconds">Timeout in seconds.</param>
    /// <param name="cancellationToken">Original cancellation token.</param>
    /// <returns>Combined cancellation token with timeout.</returns>
    protected internal static CancellationTokenSource CreateTimeoutCancellationToken(int timeoutSeconds, CancellationToken cancellationToken)
    {
        CancellationTokenSource timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        CancellationTokenSource combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        combinedCts.Token.Register(timeoutCts.Dispose);
        return combinedCts;
    }

    /// <summary>
    /// Writes a JSON result to the specified output file.
    /// </summary>
    /// <param name="outputPath">Path to write the JSON result.</param>
    /// <param name="result">The object to serialize as JSON.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="logger">Optional logger for status reporting.</param>
    protected internal static async Task WriteJsonResult(string outputPath, object result, CancellationToken cancellationToken, IPluginLogger? logger = null)
    {
        try
        {
            JsonSerializerOptions options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            string json = JsonSerializer.Serialize(result, options);
            await File.WriteAllTextAsync(outputPath, json, cancellationToken);
            logger?.LogInformation($"Result written to: {outputPath}");
        }
        catch (Exception ex)
        {
            logger?.LogWarning($"Failed to write result to {outputPath}: {ex.Message}");
        }
    }

    /// <summary>
    /// Prints operation status information.
    /// </summary>
    /// <param name="logger">The logger to use for output.</param>
    /// <param name="operation">The operation being performed.</param>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="additionalInfo">Optional additional information to display.</param>
    protected void PrintOperationStatus(IPluginLogger logger, string operation, string payloadPath, string signaturePath, string? additionalInfo = null)
    {
        logger.LogInformation($"{operation} indirect COSE Sign1 message...");
        logger.LogVerbose($"  Payload: {payloadPath}");
        logger.LogVerbose($"  Signature: {signaturePath}");
        
        if (!string.IsNullOrEmpty(additionalInfo))
        {
            logger.LogVerbose($"  {additionalInfo}");
        }
    }

    /// <summary>
    /// Handles common exceptions and returns appropriate exit codes.
    /// </summary>
    /// <param name="ex">The exception to handle.</param>
    /// <param name="configuration">Configuration for getting timeout value in error messages.</param>
    /// <param name="cancellationToken">The original cancellation token to check if operation was cancelled.</param>
    /// <param name="logger">Optional logger for error reporting.</param>
    /// <returns>Appropriate PluginExitCode for the exception type.</returns>
    protected internal static PluginExitCode HandleCommonException(Exception ex, IConfiguration configuration, CancellationToken cancellationToken, IPluginLogger? logger = null)
    {
        return ex switch
        {
            ArgumentNullException argEx => 
                HandleError($"Missing required argument - {argEx.ParamName}", PluginExitCode.MissingRequiredOption, logger, ex),
            
            FileNotFoundException fileEx => 
                HandleError($"File not found - {fileEx.Message}", PluginExitCode.UserSpecifiedFileNotFound, logger, ex),
            
            OperationCanceledException when cancellationToken.IsCancellationRequested => 
                HandleError("Operation was cancelled.", PluginExitCode.UnknownError, logger, ex),
            
            OperationCanceledException => 
                HandleError($"Operation timed out after {GetOptionalValue(configuration, "timeout", "30")} seconds.", PluginExitCode.UnknownError, logger, ex),

            ArgumentException argEx =>
                HandleError($"Invalid argument - {argEx.Message}", PluginExitCode.InvalidArgumentValue, logger, ex),

            CryptographicException cryptoEx =>
                HandleError($"Cryptographic error - {cryptoEx.Message}", PluginExitCode.CertificateLoadFailure, logger, ex),
            
            _ => 
                HandleError(ex.Message, PluginExitCode.UnknownError, logger, ex)
        };

        static PluginExitCode HandleError(string message, PluginExitCode code, IPluginLogger? logger, Exception ex)
        {
            logger?.LogError(message);
            logger?.LogException(ex);
            return code;
        }
    }

    /// <summary>
    /// Allows derived classes to add additional file validation requirements.
    /// </summary>
    /// <param name="requiredFiles">Dictionary to add additional required files to.</param>
    /// <param name="configuration">Command configuration.</param>
    protected virtual void AddAdditionalFileValidation(Dictionary<string, string?> requiredFiles, IConfiguration configuration)
    {
        // Default implementation - no additional files required
    }

    /// <summary>
    /// Gets the base usage string common to all indirect signature commands.
    /// </summary>
    protected virtual string GetBaseUsage(string commandName, string verb)
    {
        return $"CoseSignTool {commandName} --payload <payload-file> --signature <signature-file> [options]{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"Required arguments:{Environment.NewLine}" +
               $"  --payload       The file path to the payload to {verb}{Environment.NewLine}" +
               $"  --signature     The file path to the COSE Sign1 signature file{Environment.NewLine}" +
               $"{Environment.NewLine}" +
               $"Optional arguments:{Environment.NewLine}" +
               $"  --output        File path where {verb} result will be written{Environment.NewLine}" +
               $"  --timeout       Timeout in seconds for the operation (default: 30){Environment.NewLine}" +
               $"  --content-type  The content type of the payload (default: application/octet-stream){Environment.NewLine}" +
               $"  --hash-algorithm The hash algorithm to use (SHA256, SHA384, SHA512, default: SHA256){Environment.NewLine}" +
               $"  --signature-version The indirect signature version (CoseHashEnvelope, default: CoseHashEnvelope){Environment.NewLine}" +
               CoseHeaderHelper.HeaderUsage;
    }

    /// <summary>
    /// Parses the revocation mode string and returns the corresponding X509RevocationMode enum value.
    /// </summary>
    /// <param name="revocationModeString">The revocation mode string (case-insensitive).</param>
    /// <param name="defaultMode">The default mode to use if parsing fails.</param>
    /// <returns>The parsed X509RevocationMode value.</returns>
    protected internal static X509RevocationMode ParseRevocationMode(string? revocationModeString, X509RevocationMode defaultMode = X509RevocationMode.NoCheck)
    {
        if (string.IsNullOrEmpty(revocationModeString))
        {
            return defaultMode;
        }

        if (Enum.TryParse<X509RevocationMode>(revocationModeString, ignoreCase: true, out X509RevocationMode result))
        {
            return result;
        }

        // This should not be reached since validation happens earlier
        return defaultMode;
    }

    /// <summary>
    /// Gets command-specific examples. Must be implemented by derived classes.
    /// </summary>
    protected abstract string GetExamples();

    /// <summary>
    /// Gets additional optional arguments specific to the command.
    /// </summary>
    protected virtual string GetAdditionalOptionalArguments()
    {
        return string.Empty;
    }
}
