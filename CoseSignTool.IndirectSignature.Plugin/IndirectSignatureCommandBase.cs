// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin;

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
        { "store-location", "The location of the local certificate store (default: CurrentUser)" }
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
    /// Header options for customizing COSE headers.
    /// </summary>
    protected static readonly Dictionary<string, string> HeaderOptions = CoseHeaderHelper.HeaderOptions;

    /// <summary>
    /// Validates common parameters and returns parsed timeout value.
    /// </summary>
    /// <param name="configuration">The configuration containing command arguments.</param>
    /// <param name="timeoutSeconds">The parsed timeout value in seconds.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected internal static PluginExitCode ValidateCommonParameters(IConfiguration configuration, out int timeoutSeconds)
    {
        string timeoutString = GetOptionalValue(configuration, "timeout", "30") ?? "30";
        
        if (!int.TryParse(timeoutString, out timeoutSeconds) || timeoutSeconds <= 0)
        {
            Console.Error.WriteLine("Error: Invalid timeout value. Must be a positive integer.");
            return PluginExitCode.InvalidArgumentValue;
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Validates that required file paths exist.
    /// </summary>
    /// <param name="requiredFiles">Dictionary of file descriptions to file paths.</param>
    /// <returns>PluginExitCode indicating validation result.</returns>
    protected internal static PluginExitCode ValidateFilePaths(Dictionary<string, string?> requiredFiles)
    {
        foreach (KeyValuePair<string, string?> kvp in requiredFiles)
        {
            if (string.IsNullOrWhiteSpace(kvp.Value))
            {
                Console.Error.WriteLine($"Error: {kvp.Key} file path is required.");
                return PluginExitCode.MissingRequiredOption;
            }

            if (!File.Exists(kvp.Value))
            {
                Console.Error.WriteLine($"Error: {kvp.Key} file not found: {kvp.Value}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }
        }

        return PluginExitCode.Success;
    }

    /// <summary>
    /// Loads a certificate for signing operations.
    /// </summary>
    /// <param name="configuration">The configuration containing certificate parameters.</param>
    /// <returns>A tuple containing the certificate and any additional certificates, or null on failure.</returns>
    protected internal static (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) LoadSigningCertificate(IConfiguration configuration)
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
                    Console.Error.WriteLine($"Error: Certificate file not found: {pfxPath}");
                    return (null, null, PluginExitCode.UserSpecifiedFileNotFound);
                }

                X509Certificate2Collection collection = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057 // Type or member is obsolete
                collection.Import(pfxPath, password, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057 // Type or member is obsolete

                if (collection.Count == 0)
                {
                    Console.Error.WriteLine("Error: No certificates found in PFX file.");
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
                    Console.Error.WriteLine("Error: No certificate with private key found in PFX file.");
                    return (null, null, PluginExitCode.CertificateLoadFailure);
                }

                return (signingCert, additionalCerts.Count > 0 ? additionalCerts : null, PluginExitCode.Success);
            }
            else if (!string.IsNullOrEmpty(thumbprint))
            {
                if (!Enum.TryParse<StoreLocation>(storeLocation, true, out StoreLocation storeLocationEnum))
                {
                    Console.Error.WriteLine($"Error: Invalid store location: {storeLocation}");
                    return (null, null, PluginExitCode.InvalidArgumentValue);
                }

                using X509Store store = new X509Store(storeName, storeLocationEnum);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection collection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (collection.Count == 0)
                {
                    Console.Error.WriteLine($"Error: Certificate with thumbprint {thumbprint} not found in store {storeName}/{storeLocation}");
                    return (null, null, PluginExitCode.UserSpecifiedFileNotFound);
                }

                X509Certificate2 cert = collection[0];
                if (!cert.HasPrivateKey)
                {
                    Console.Error.WriteLine("Error: Certificate does not have a private key.");
                    return (null, null, PluginExitCode.CertificateLoadFailure);
                }

                return (cert, null, PluginExitCode.Success);
            }
            else
            {
                Console.Error.WriteLine("Error: Either --pfx or --thumbprint must be specified for signing operations.");
                return (null, null, PluginExitCode.MissingRequiredOption);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error loading certificate: {ex.Message}");
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
    protected internal static async Task WriteJsonResult(string outputPath, object result, CancellationToken cancellationToken)
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
            Console.WriteLine($"Result written to: {outputPath}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: Failed to write result to {outputPath}: {ex.Message}");
        }
    }

    /// <summary>
    /// Prints operation status information to the console.
    /// </summary>
    /// <param name="operation">The operation being performed.</param>
    /// <param name="payloadPath">Path to the payload file.</param>
    /// <param name="signaturePath">Path to the signature file.</param>
    /// <param name="additionalInfo">Optional additional information to display.</param>
    protected static void PrintOperationStatus(string operation, string payloadPath, string signaturePath, string? additionalInfo = null)
    {
        Console.WriteLine($"{operation} indirect COSE Sign1 message...");
        Console.WriteLine($"  Payload: {payloadPath}");
        Console.WriteLine($"  Signature: {signaturePath}");
        
        if (!string.IsNullOrEmpty(additionalInfo))
        {
            Console.WriteLine($"  {additionalInfo}");
        }
    }

    /// <summary>
    /// Handles common exceptions and returns appropriate exit codes.
    /// </summary>
    /// <param name="ex">The exception to handle.</param>
    /// <param name="configuration">Configuration for getting timeout value in error messages.</param>
    /// <param name="cancellationToken">The original cancellation token to check if operation was cancelled.</param>
    /// <returns>Appropriate PluginExitCode for the exception type.</returns>
    protected internal static PluginExitCode HandleCommonException(Exception ex, IConfiguration configuration, CancellationToken cancellationToken)
    {
        return ex switch
        {
            ArgumentNullException argEx => 
                HandleError($"Missing required argument - {argEx.ParamName}", PluginExitCode.MissingRequiredOption),
            
            FileNotFoundException fileEx => 
                HandleError($"File not found - {fileEx.Message}", PluginExitCode.UserSpecifiedFileNotFound),
            
            OperationCanceledException when cancellationToken.IsCancellationRequested => 
                HandleError("Operation was cancelled.", PluginExitCode.UnknownError),
            
            OperationCanceledException => 
                HandleError($"Operation timed out after {GetOptionalValue(configuration, "timeout", "30")} seconds.", PluginExitCode.UnknownError),

            ArgumentException argEx =>
                HandleError($"Invalid argument - {argEx.Message}", PluginExitCode.InvalidArgumentValue),

            CryptographicException cryptoEx =>
                HandleError($"Cryptographic error - {cryptoEx.Message}", PluginExitCode.CertificateLoadFailure),
            
            _ => 
                HandleError(ex.Message, PluginExitCode.UnknownError)
        };

        static PluginExitCode HandleError(string message, PluginExitCode code)
        {
            Console.Error.WriteLine($"Error: {message}");
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
