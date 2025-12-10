// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Signs a file with a COSE signature based on passed in command line arguments.
/// </summary>
public class SignCommand : CoseCommand
{
    /// <summary>
    /// A map of command line options to their abbreviated aliases.
    /// </summary>
    private static readonly Dictionary<string, string> PrivateOptions = new()
    {
        ["-EmbedPayload"] = "EmbedPayload",
        ["-ep"] = "EmbedPayload",
        ["-PipeOutput"] = "PipeOutput",
        ["-po"] = "PipeOutput",
        ["-PfxCertificate"] = "PfxCertificate",
        ["-pfx"] = "PfxCertificate",
        ["-Password"] = "Password",
        ["-pw"] = "Password",
        ["-Thumbprint"] = "Thumbprint",
        ["-th"] = "Thumbprint",
        ["-StoreName"] = "StoreName",
        ["-sn"] = "StoreName",
        ["-StoreLocation"] = "StoreLocation",
        ["-sl"] = "StoreLocation",
        ["-ContentType"] = "ContentType",
        ["-cty"] = "ContentType",
        ["-IntHeaders"] = "IntHeaders",
        ["-ih"] = "IntHeaders",
        ["-StringHeaders"] = "StringHeaders",
        ["-sh"] = "StringHeaders",
        ["-IntProtectedHeaders"] = "IntProtectedHeaders",
        ["-iph"] = "IntProtectedHeaders",
        ["-StringProtectedHeaders"] = "StringProtectedHeaders",
        ["-sph"] = "StringProtectedHeaders",
        ["-IntUnProtectedHeaders"] = "IntUnProtectedHeaders",
        ["-iuh"] = "IntUnProtectedHeaders",
        ["-StringUnProtectedHeaders"] = "StringUnProtectedHeaders",
        ["-suh"] = "StringUnProtectedHeaders",
        ["-CwtIssuer"] = "CwtIssuer",
        ["-cwt-iss"] = "CwtIssuer",
        ["-CwtSubject"] = "CwtSubject",
        ["-cwt-sub"] = "CwtSubject",
        ["-CwtAudience"] = "CwtAudience",
        ["-cwt-aud"] = "CwtAudience",
        ["-CwtClaims"] = "CwtClaims",
        ["-cwt"] = "CwtClaims",
        ["-EnableScittCompliance"] = "EnableScittCompliance",
        ["-scitt"] = "EnableScittCompliance",
        ["-CertProvider"] = "CertProvider",
        ["-cp"] = "CertProvider"
    };

    // Inherited default values
    private const string DefaultStoreName = "My";
    private const string DefaultStoreLocation = "CurrentUser";

    private IEnumerable<KeyValuePair<string, int>> ProtectedHeadersInteger { get; set; }

    private IEnumerable<KeyValuePair<string, int>> ProtectedHeadersString { get; set; }

    //<inheritdoc />
    public static new readonly Dictionary<string, string> Options =
        CoseCommand.Options.Concat(PrivateOptions).ToDictionary(k => k.Key, k => k.Value);

    #region Public properties
    /// <summary>
    /// Optional. If true, encrypts and embeds the payload in the in COSE signature file.
    /// Default behavior is 'detached signing', where the signature is in a separate file from the payload.
    /// Note that embed-signed files are not readable by standard text editors.
    /// </summary>
    public bool EmbedPayload { get; set; }

    /// <summary>
    /// Optional. If true, writes signature output to the STDOUT channel so it can be piped to another program instead of writing to file.
    /// </summary>
    public bool PipeOutput { get; set; }

    /// <summary>
    /// Optional. Gets or sets the path to a .pfx file containing the private key certificate to sign with.
    /// </summary>
    public string? PfxCertificate { get; set; }

    /// <summary>
    /// Optional. Gets or sets the password for the .pfx file if it requires one.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Optional. Gets or sets the SHA1 thumbprint of a certificate in the Certificate Store to sign the file with.
    /// </summary>
    public string? Thumbprint { get; set; }

    /// <summary>
    /// Optional. Gets or sets the name of the Certificate Store to look for the signing certificate in.
    /// Default value is 'My'.
    /// </summary>
    public string? StoreName { get; set; }

    /// <summary>
    /// Optional. Gets or sets the location of the Certificate Store to look for the signing certificate in.
    /// Default value is StoreLocation.CurrentUser.
    /// </summary>
    public StoreLocation StoreLocation { get; set; }

    /// <summary>
    /// Optional. Gets or sets the content type of the payload to be set in protected header. Default value is "application/cose".
    /// </summary>
    public string? ContentType { get; set; }

    /// <summary>
    /// Optional. Gets or sets the headers with Int32 values.
    /// </summary>
    public List<CoseHeader<int>>? IntHeaders { get; set; }

    /// <summary>
    /// Optional. Gets or sets the headers with string values.
    /// </summary>
    public List<CoseHeader<string>>? StringHeaders { get; set; }

    /// <summary>
    /// Optional. Gets or sets the CWT issuer (iss) claim for SCITT compliance.
    /// If not specified and EnableScittCompliance is true, defaults to DID:x509 derived from the certificate.
    /// </summary>
    public string? CwtIssuer { get; set; }

    /// <summary>
    /// Optional. Gets or sets the CWT subject (sub) claim for SCITT compliance.
    /// If not specified and EnableScittCompliance is true, defaults to "unknown.intent".
    /// </summary>
    public string? CwtSubject { get; set; }

    /// <summary>
    /// Optional. Gets or sets the CWT audience (aud) claim for SCITT compliance.
    /// </summary>
    public string? CwtAudience { get; set; }

    /// <summary>
    /// Optional. Gets or sets additional custom CWT claims as a list of label:value pairs.
    /// Labels can be integers (e.g., "100:value") or RFC 8392 claim names (e.g., "cti:abc123").
    /// Multiple claims can be specified by repeating the argument.
    /// Example: -cwt "cti:abc123" -cwt "100:custom-value" -cwt "exp:1735689600"
    /// </summary>
    public List<string>? CwtClaims { get; set; }

    /// <summary>
    /// Optional. If true, automatically adds SCITT-compliant CWT claims (issuer and subject) to the signature.
    /// This is enabled by default for certificate-based signing.
    /// </summary>
    public bool EnableScittCompliance { get; set; } = true;

    /// <summary>
    /// Optional. Gets or sets the name of the certificate provider plugin to use for signing.
    /// If not specified, uses local certificate loading (PFX or thumbprint).
    /// </summary>
    public string? CertProvider { get; set; }

    #endregion

    /// <summary>
    /// Internal field to store the configuration provider for plugin access.
    /// </summary>
    private readonly CommandLineConfigurationProvider? ConfigurationProvider;

    /// <summary>
    /// Internal field to store the plugin manager for certificate providers.
    /// </summary>
    private CertificateProviderPluginManager? PluginManager;

    /// <summary>
    /// For test use only.
    /// </summary>
    internal SignCommand() { }

    /// <summary>
    /// Creates a SignCommand instance and sets its properties with a CommandLineConfigurationProvider.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider that has loaded the command line arguments.</param>
    public SignCommand(CommandLineConfigurationProvider provider)
    {
        ConfigurationProvider = provider;
        ApplyOptions(provider);
    }

    /// <summary>
    /// Sets the certificate provider plugin manager for this command instance.
    /// </summary>
    /// <param name="manager">The plugin manager to use for loading certificate providers.</param>
    internal void SetCertificateProviderPluginManager(CertificateProviderPluginManager manager)
    {
        PluginManager = manager;
    }

    /// <summary>
    /// Generates a cose signed document for the given certificate and payload
    /// </summary>
    /// <returns>An exit code indicating success or failure.</returns>
    /// <exception cref="FileNotFoundException">The specified payload file or certificate file could not be found.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The output path could not be determined.
    /// If neither SignatureFile nor PipeOutput are set, CoseSignTool attempts to create a default output file based on PayloadFile.</exception>
    /// <exception cref="ArgumentNullException">No certificate filepath or thumbprint was given.</exception>
    public override ExitCode Run()
    {
        // Get the payload as a Stream, either piped in or from file.
        ExitCode exitCode = TryGetStreamFromPipeOrFile(PayloadFile, nameof(PayloadFile), out Stream? payloadStream);
        if (exitCode != ExitCode.Success || payloadStream is null)
        {
            return exitCode;
        }

        // Get the signing key provider (either from certificate provider plugin or local certificate).
        ICoseSigningKeyProvider signingKeyProvider;
        try
        {
            signingKeyProvider = LoadSigningKeyProvider();
        }
        catch (Exception ex) when (ex is CoseSign1CertificateException or FileNotFoundException or CryptographicException or ArgumentException or InvalidOperationException)
        {
            exitCode = ex is CoseSign1CertificateException ? ExitCode.StoreCertificateNotFound : ExitCode.CertificateLoadFailure;
            return CoseSignTool.Fail(exitCode, ex);
        }

        // Make sure we know where to write the signature to.
        if (SignatureFile is null && !PipeOutput)
        {
            if (PayloadFile is null)
            {
                return CoseSignTool.Fail(
                    ExitCode.MissingRequiredOption, null,
                    "CoseSignTool could not determine a path to write the signature file to.");
            }

            string extension = EmbedPayload ? "csm" : "cose";
            SignatureFile = new FileInfo($"{PayloadFile.FullName}.{extension}");
        }

        try
        {
            // Use shared header processing logic
            ICoseHeaderExtender? headerExtender = CoseHeaderHelper.CreateHeaderExtender(IntHeaders, StringHeaders);

            // If CWT claims customization is requested, create a CWT extender
            // Note: CertificateCoseSigningKeyProvider now automatically adds default CWT claims for SCITT compliance
            // We only need to create a customizer if the user wants to override defaults
            if (CwtIssuer != null || CwtSubject != null || CwtAudience != null || (CwtClaims != null && CwtClaims.Count > 0))
            {
                // Create a CWT claims extender with user-specified values
                // This will merge with and override the automatic defaults from CertificateCoseSigningKeyProvider
                CWTClaimsHeaderExtender cwtCustomizer = new();

                // Override issuer if specified
                if (CwtIssuer != null)
                {
                    cwtCustomizer.SetIssuer(CwtIssuer);
                }

                // Override subject if specified
                if (CwtSubject != null)
                {
                    cwtCustomizer.SetSubject(CwtSubject);
                }

                // Add audience if specified
                if (CwtAudience != null)
                {
                    cwtCustomizer.SetAudience(CwtAudience);
                }

                // Apply any custom CWT claims specified via CwtClaims
                if (CwtClaims != null && CwtClaims.Count > 0)
                {
                    ApplyCwtClaims(cwtCustomizer, CwtClaims);
                }

                // Chain the CWT customizer with any existing header extender
                if (headerExtender != null)
                {
                    headerExtender = new CoseSign1.Headers.ChainedCoseHeaderExtender(new[] { cwtCustomizer, headerExtender });
                }
                else
                {
                    headerExtender = cwtCustomizer;
                }
            }

            // Create a cancellation token with timeout (default 30 seconds from MaxWaitTime)
            using CancellationTokenSource timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(MaxWaitTime));
            
            // Generate the COSE signature asynchronously with cancellation support.
            ReadOnlyMemory<byte> signedBytes = CoseHandler.SignAsync(
                payloadStream, 
                signingKeyProvider, 
                EmbedPayload, 
                SignatureFile, 
                ContentType ?? CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE, 
                headerExtender,
                timeoutCts.Token).ConfigureAwait(false).GetAwaiter().GetResult();
            
            // Write the signature to stream or file.
            if (PipeOutput)
            {
                WriteToStdOut(signedBytes);
            }
            else
            {
                // SignatureFile?.WriteAllBytesResilient(signedBytes.ToArray());
                File.WriteAllBytes(SignatureFile!.FullName, signedBytes.ToArray());
            }

            return ExitCode.Success;           
        }
        catch (ArgumentException ex)
        {
            return CoseSignTool.Fail(ExitCode.PayloadReadError, ex);
        }
        catch (InvalidOperationException ex)
        {
            return CoseSignTool.Fail(ExitCode.UnknownError, ex);
        }
        catch (Exception ex) when (ex is CryptographicException or CoseSign1CertificateException)
        {
            // The certificate was not valid for COSE signing.
            return CoseSignTool.Fail(ExitCode.CertificateLoadFailure, ex);
        }
        finally
        {
            payloadStream.HardDispose();
        }
    }

    //<inheritdoc />
    protected internal override void ApplyOptions(CommandLineConfigurationProvider provider)
    {
        EmbedPayload = GetOptionBool(provider, nameof(EmbedPayload));
        PipeOutput = GetOptionBool(provider, nameof (PipeOutput));
        Thumbprint = GetOptionString(provider, nameof(Thumbprint));
        PfxCertificate = GetOptionString(provider, nameof(PfxCertificate));
        Password = GetOptionString(provider, nameof(Password));
        ContentType = GetOptionString(provider, nameof(ContentType), CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE);
        StoreName = GetOptionString(provider, nameof(StoreName), DefaultStoreName);
        string? sl = GetOptionString(provider, nameof(StoreLocation), DefaultStoreLocation);
        StoreLocation = sl is not null ? Enum.Parse<StoreLocation>(sl) : StoreLocation.CurrentUser;
        IntHeaders = GetOptionHeadersFromFile<int>(provider, nameof(IntHeaders), null);
        StringHeaders = GetOptionHeadersFromFile<string>(provider, nameof(StringHeaders), null, new HeaderStringConverter());

        if (IntHeaders == null)
        {
            IntHeaders = new();

            // IntProtectedHeaders
            GetOptionHeadersFromCommandLine(provider, "IntProtectedHeaders", true, HeaderValueConverter<int>, IntHeaders);

            // IntUnProtectedHeaders
            GetOptionHeadersFromCommandLine(provider, "IntUnProtectedHeaders", false, HeaderValueConverter<int>, IntHeaders);
        }
        
        if (StringHeaders == null)
        {
            StringHeaders = new();

            // StringProtectedHeaders
            GetOptionHeadersFromCommandLine(provider, "StringProtectedHeaders", true, HeaderValueConverter<string>, StringHeaders);

            // StringUnProtectedHeaders
            GetOptionHeadersFromCommandLine(provider, "StringUnProtectedHeaders", false, HeaderValueConverter<string>, StringHeaders);
        }

        // CWT Claims options
        CwtIssuer = GetOptionString(provider, nameof(CwtIssuer));
        CwtSubject = GetOptionString(provider, nameof(CwtSubject));
        CwtAudience = GetOptionString(provider, nameof(CwtAudience));
        
        // Custom CWT claims (can be specified multiple times)
        if (provider.TryGet(nameof(CwtClaims), out string? cwtClaimsValue) && !string.IsNullOrWhiteSpace(cwtClaimsValue))
        {
            CwtClaims = new List<string> { cwtClaimsValue };
            // Check for additional CWT claims with indexed keys (CwtClaims:0, CwtClaims:1, etc.)
            int index = 1;
            while (provider.TryGet($"{nameof(CwtClaims)}:{index}", out string? additionalClaim) && !string.IsNullOrWhiteSpace(additionalClaim))
            {
                CwtClaims.Add(additionalClaim);
                index++;
            }
        }
        
        // Enable SCITT compliance by default
        bool scittComplianceSet = provider.TryGet(nameof(EnableScittCompliance), out string? scittValue);
        EnableScittCompliance = !scittComplianceSet || (bool.TryParse(scittValue, out bool scittResult) && scittResult);

        // Certificate provider plugin
        CertProvider = GetOptionString(provider, nameof(CertProvider));

        base.ApplyOptions(provider);
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
    /// A helper method to convert the header value to the required type.
    /// </summary>
    /// <typeparam name="TypeV">The type of the header value.</typeparam>
    /// <param name="labelValue">A string array containing the header label and value.</param>
    /// <returns>The value converted to the correct type.</returns>
    /// <exception cref="ArgumentException">Throws if the conversion failed.</exception>
    private static TypeV HeaderValueConverter<TypeV>(string[]? labelValue = null)
    {
        if(labelValue == null || labelValue.Length < 2)
        {
            throw new ArgumentException("Invalid header. Header label and value must be provided.");
        }

        // Validate label
        if (string.IsNullOrEmpty(labelValue[0]))
        {
            throw new ArgumentException("Header label cannot be null");
        }

        // Validate value
        switch (typeof(TypeV))
        {
            case var x when x == typeof(int):
                if (!int.TryParse(labelValue[1], out int value))
                {
                    throw new ArgumentException($"Invalid header int32 value {labelValue[1]}");
                }

                return (TypeV)Convert.ChangeType(value, typeof(TypeV));
            case var x when x == typeof(string):
                if(string.IsNullOrEmpty(labelValue[1]))
                {
                    throw new ArgumentException($"Invalid header string value {labelValue[1]}");
                }

                return (TypeV)Convert.ChangeType(labelValue[1], typeof(TypeV));
            default:
                throw new ArgumentException($"Header value of type {typeof(TypeV)} is not supported.");
        }
    }

    /// <summary>
    /// Tries to load the certificate to sign with.
    /// </summary>
    /// <returns>The certificate if found and optional additional root certificates from PFX.</returns>
    /// <exception cref="ArgumentOutOfRangeException">User passed in a thumbprint instead of a file path on a non-Windows OS.</exception>
    /// <exception cref="ArgumentNullException">No certificate filepath or thumbprint was given.</exception>
    /// <exception cref="CryptographicException">The certificate was found but could not be loaded
    /// -- OR --
    /// The certificate required a password and the user did not supply one, or the user-supplied password was wrong.</exception>
    internal (X509Certificate2 certificate, List<X509Certificate2>? additionalRoots) LoadCert()
    {
        X509Certificate2 cert;
        List<X509Certificate2>? additionalRoots = null;
        
        if (PfxCertificate is not null)
        {
            // Load the PFX certificate. This will throw a CryptographicException if the password is wrong or missing.
            ThrowIfMissing(PfxCertificate, "Could not find the certificate file");
            
            // Load the PFX as a certificate store to extract all certificates
            X509Certificate2Collection pfxCertificates = [];
            pfxCertificates.Import(PfxCertificate, Password, X509KeyStorageFlags.Exportable);

            // Build the certificate chain in leaf-first order
            List<X509Certificate2> chainedCertificates = BuildCertificateChain(pfxCertificates, Thumbprint);
            
            if (chainedCertificates.Count == 0)
            {
                throw new CoseSign1CertificateException(string.IsNullOrEmpty(Thumbprint) 
                    ? "No valid certificate chain found in PFX file"
                    : $"No certificate with private key and thumbprint '{Thumbprint}' found in PFX file");
            }
            
            // The first certificate in the chain is the signing certificate (leaf)
            cert = chainedCertificates[0];
            
            // The remaining certificates are the chain (intermediate and root)
            additionalRoots = chainedCertificates.Skip(1).ToList();
        }
        else
        {
            // Load certificate from thumbprint.
            cert = Thumbprint is not null ? CoseHandler.LookupCertificate(Thumbprint, StoreName!, StoreLocation) :
                throw new ArgumentNullException("You must specify a certificate file or thumbprint to sign with.");
        }

        return (cert, additionalRoots);
    }

    /// <summary>
    /// Loads a signing key provider, either from a certificate provider plugin or from local certificates.
    /// </summary>
    /// <returns>An ICoseSigningKeyProvider instance ready for signing operations.</returns>
    /// <exception cref="ArgumentException">Thrown when certificate provider is specified but not found, or when configuration is invalid.</exception>
    /// <exception cref="InvalidOperationException">Thrown when certificate provider fails to create a provider.</exception>
    /// <exception cref="FileNotFoundException">Thrown when a specified certificate file is not found.</exception>
    /// <exception cref="CryptographicException">Thrown when certificate loading or validation fails.</exception>
    /// <exception cref="CoseSign1CertificateException">Thrown when certificate store lookup fails.</exception>
    internal ICoseSigningKeyProvider LoadSigningKeyProvider()
    {
        // If a certificate provider is specified, use it
        if (!string.IsNullOrWhiteSpace(CertProvider))
        {
            return LoadSigningKeyProviderFromPlugin();
        }

        // Otherwise, use local certificate loading (legacy behavior)
        return LoadSigningKeyProviderFromLocalCertificate();
    }

    /// <summary>
    /// Loads a signing key provider from a certificate provider plugin.
    /// </summary>
    /// <returns>An ICoseSigningKeyProvider instance from the plugin.</returns>
    /// <exception cref="ArgumentException">Thrown when certificate provider is not found or cannot create provider.</exception>
    /// <exception cref="InvalidOperationException">Thrown when certificate provider fails during creation.</exception>
    private ICoseSigningKeyProvider LoadSigningKeyProviderFromPlugin()
    {
        if (PluginManager == null)
        {
            throw new InvalidOperationException(
                $"Certificate provider '{CertProvider}' was specified, but no certificate provider plugins are available. " +
                "Ensure certificate provider plugins are installed and the plugins directory is correctly configured.");
        }

        ICertificateProviderPlugin? plugin = PluginManager.GetProvider(CertProvider!);
        if (plugin == null)
        {
            string availableProviders = PluginManager.Providers.Count > 0
                ? string.Join(", ", PluginManager.Providers.Keys)
                : "none";
            throw new ArgumentException(
                $"Certificate provider '{CertProvider}' not found. Available providers: {availableProviders}");
        }

        // Convert the CommandLineConfigurationProvider to IConfiguration (explicit cast)
        // CommandLineConfigurationProvider implements IConfigurationProvider, not IConfiguration
        // We need to access it as IConfiguration through the ConfigurationRoot
        if (ConfigurationProvider == null)
        {
            throw new InvalidOperationException("Configuration provider is not available.");
        }

        // Create an IConfiguration from the provider
        using ConfigurationRoot configRoot = new ConfigurationRoot(new List<IConfigurationProvider> { ConfigurationProvider });
        IConfiguration configuration = configRoot;

        // Check if the plugin can create a provider with the given configuration
        if (!plugin.CanCreateProvider(configuration))
        {
            throw new ArgumentException(
                $"Certificate provider '{CertProvider}' cannot create a provider with the given configuration. " +
                $"Required parameters may be missing. Use 'CoseSignTool help {CertProvider}' for usage information.");
        }

        // Create and return the provider
        // Note: We could pass a logger here if we had one available
        ICoseSigningKeyProvider provider = plugin.CreateProvider(configuration, logger: null);
        
        // If the provider is a certificate-based provider, set the EnableScittCompliance flag
        if (provider is CoseSign1.Certificates.CertificateCoseSigningKeyProvider certProvider)
        {
            certProvider.EnableScittCompliance = EnableScittCompliance;
        }
        
        return provider;
    }

    /// <summary>
    /// Loads a signing key provider from local certificate (PFX or thumbprint).
    /// </summary>
    /// <returns>An ICoseSigningKeyProvider instance using local certificates.</returns>
    private ICoseSigningKeyProvider LoadSigningKeyProviderFromLocalCertificate()
    {
        (X509Certificate2 cert, List<X509Certificate2>? additionalRoots) = LoadCert();
        return new CoseSign1.Certificates.Local.X509Certificate2CoseSigningKeyProvider(
            certificateChainBuilder: null,
            signingCertificate: cert,
            rootCertificates: additionalRoots,
            enableScittCompliance: EnableScittCompliance);
    }

    /// <summary>
    /// Builds a certificate chain from a collection of certificates, ordering them from leaf to root.
    /// </summary>
    /// <param name="certificates">The collection of certificates to build the chain from.</param>
    /// <param name="targetThumbprint">Optional thumbprint to specify which certificate should be the leaf.</param>
    /// <returns>A list of certificates ordered from leaf to root.</returns>
    private static List<X509Certificate2> BuildCertificateChain(X509Certificate2Collection certificates, string? targetThumbprint = null)
    {
        List<X509Certificate2> certList = certificates.Cast<X509Certificate2>().ToList();
        List<X509Certificate2> result = new List<X509Certificate2>();
        
        // If a specific thumbprint is provided, start with that certificate
        X509Certificate2? leafCert = null;
        if (!string.IsNullOrEmpty(targetThumbprint))
        {
            leafCert = certList.FirstOrDefault(c => c.Thumbprint.Equals(targetThumbprint, StringComparison.OrdinalIgnoreCase));
            if (leafCert == null)
            {
                return result; // Return empty list if thumbprint not found
            }
        }
        else
        {
            // Find the leaf certificate (one that is not an issuer of any other certificate)
            // Priority: 1) Has private key and is not an issuer, 2) Has private key, 3) Is not an issuer
            leafCert = certList
                .Where(c => c.HasPrivateKey && !IsIssuerOfAnyCertificate(c, certList))
                .FirstOrDefault() ??
                certList
                .Where(c => c.HasPrivateKey)
                .FirstOrDefault() ??
                certList
                .Where(c => !IsIssuerOfAnyCertificate(c, certList))
                .FirstOrDefault();
        }
        
        if (leafCert == null)
        {
            return result; // No suitable leaf certificate found
        }

        // Build the chain starting from the leaf
        X509Certificate2? current = leafCert;
        HashSet<string> usedCerts = new HashSet<string>();
        
        while (current != null && !usedCerts.Contains(current.Thumbprint))
        {
            result.Add(current);
            usedCerts.Add(current.Thumbprint);
            
            // Find the issuer of the current certificate
            current = FindIssuer(current, certList.Where(c => !usedCerts.Contains(c.Thumbprint)));
        }
        
        return result;
    }
    
    /// <summary>
    /// Checks if a certificate is the issuer of any certificate in the collection.
    /// </summary>
    /// <param name="potentialIssuer">The certificate to check as a potential issuer.</param>
    /// <param name="certificates">The collection of certificates to check against.</param>
    /// <returns>True if the certificate is an issuer of any certificate in the collection.</returns>
    private static bool IsIssuerOfAnyCertificate(X509Certificate2 potentialIssuer, List<X509Certificate2> certificates)
    {
        return certificates.Any(cert => cert != potentialIssuer && IsIssuer(potentialIssuer, cert));
    }
    
    /// <summary>
    /// Finds the issuer certificate for a given certificate.
    /// </summary>
    /// <param name="certificate">The certificate to find the issuer for.</param>
    /// <param name="candidates">The collection of potential issuer certificates.</param>
    /// <returns>The issuer certificate if found, otherwise null.</returns>
    private static X509Certificate2? FindIssuer(X509Certificate2 certificate, IEnumerable<X509Certificate2> candidates)
    {
        return candidates.FirstOrDefault(issuer => IsIssuer(issuer, certificate));
    }
    
    /// <summary>
    /// Checks if one certificate is the issuer of another certificate by verifying the cryptographic signature.
    /// </summary>
    /// <param name="issuer">The potential issuer certificate.</param>
    /// <param name="subject">The subject certificate.</param>
    /// <returns>True if the issuer certificate issued the subject certificate.</returns>
    private static bool IsIssuer(X509Certificate2 issuer, X509Certificate2 subject)
    {
        // Quick check: if the issuer's subject name doesn't match the subject's issuer name, it's not the issuer
        if (!issuer.SubjectName.Name.Equals(subject.IssuerName.Name, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        
        // Handle self-signed certificates
        if (issuer.Equals(subject))
        {
            return issuer.SubjectName.Name.Equals(issuer.IssuerName.Name, StringComparison.OrdinalIgnoreCase);
        }
        
        // Verify the cryptographic signature
        try
        {
            // Use the built-in X.509 chain building to verify the relationship
            using X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(issuer);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            
            // Build the chain and check if the issuer is in the chain
            if (chain.Build(subject))
            {
                // Check if the issuer certificate is in the chain elements
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    if (element.Certificate.Thumbprint.Equals(issuer.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            
            // Fallback: manual signature verification for edge cases
            return VerifySignatureManually(issuer, subject);
        }
        catch
        {
            // If chain building fails, try manual verification
            try
            {
                return VerifySignatureManually(issuer, subject);
            }
            catch
            {
                return false;
            }
        }
    }
    
    /// <summary>
    /// Manually verifies if an issuer certificate signed a subject certificate.
    /// </summary>
    /// <param name="issuer">The potential issuer certificate.</param>
    /// <param name="subject">The subject certificate.</param>
    /// <returns>True if the signature is valid.</returns>
    private static bool VerifySignatureManually(X509Certificate2 issuer, X509Certificate2 subject)
    {
        try
        {
            // Get the public key from the issuer
            PublicKey publicKey = issuer.PublicKey;
            if (publicKey == null)
            {
                return false;
            }

            // Get the signature algorithm and signature value from the subject certificate
            Oid signatureAlgorithm = subject.SignatureAlgorithm;
            if (signatureAlgorithm == null)
            {
                return false;
            }

            // Extract the To-Be-Signed (TBS) data from the subject certificate
            // This is the raw certificate data without the signature
            byte[] rawData = subject.RawData;
            if (rawData == null || rawData.Length == 0)
            {
                return false;
            }
            
            // Parse the certificate to extract TBS and signature
            (byte[] tbsData, byte[] signatureData) = ExtractTbsAndSignature(rawData);
            if (tbsData == null || signatureData == null)
            {
                return false;
            }
            
            // Verify the signature based on the algorithm
            return signatureAlgorithm.Value switch
            {
                "1.2.840.113549.1.1.11" => VerifyRsaSha256Signature(publicKey, tbsData, signatureData), // SHA256withRSA
                "1.2.840.113549.1.1.5" => VerifyRsaSha1Signature(publicKey, tbsData, signatureData),   // SHA1withRSA
                "1.2.840.10045.4.3.2" => VerifyEcdsaSha256Signature(publicKey, tbsData, signatureData), // SHA256withECDSA
                "1.2.840.10045.4.1" => VerifyEcdsaSha1Signature(publicKey, tbsData, signatureData),     // SHA1withECDSA
                _ => false // Unsupported algorithm
            };
        }
        catch
        {
            return false;
        }
    }
    
    /// <summary>
    /// Extracts the To-Be-Signed (TBS) data and signature from a certificate's raw data.
    /// </summary>
    /// <param name="rawData">The raw certificate data.</param>
    /// <returns>A tuple containing the TBS data and signature data.</returns>
    private static (byte[]? tbsData, byte[]? signatureData) ExtractTbsAndSignature(byte[] rawData)
    {
        try
        {
            // Use AsnReader to parse the certificate structure
            System.Formats.Asn1.AsnReader reader = new System.Formats.Asn1.AsnReader(rawData, System.Formats.Asn1.AsnEncodingRules.DER);
            System.Formats.Asn1.AsnReader certSequence = reader.ReadSequence();

            // Read the TBS certificate (first element) by marking position and reading
            System.Formats.Asn1.AsnReader tbsReader = certSequence.ReadSequence();
            byte[] tbsData = tbsReader.ReadEncodedValue().ToArray();
            
            // Skip the signature algorithm identifier (second element)
            certSequence.ReadSequence();

            // Read the signature value (third element)
            byte[] signatureData = certSequence.ReadBitString(out _);
            
            return (tbsData, signatureData);
        }
        catch
        {
            return (null, null);
        }
    }
    
    /// <summary>
    /// Verifies an RSA-SHA256 signature.
    /// </summary>
    private static bool VerifyRsaSha256Signature(PublicKey publicKey, byte[] tbsData, byte[] signature)
    {
        try
        {
            using RSA? rsa = publicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                return false;
            }
            
            return rsa.VerifyData(tbsData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }
    
    /// <summary>
    /// Verifies an RSA-SHA1 signature.
    /// </summary>
    private static bool VerifyRsaSha1Signature(PublicKey publicKey, byte[] tbsData, byte[] signature)
    {
        try
        {
            using RSA? rsa = publicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                return false;
            }
            
            return rsa.VerifyData(tbsData, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1); // CodeQL [SM02196] This is to support certificates or other singers which use SHA1 with RSA for validation only.
        }
        catch
        {
            return false;
        }
    }
    
    /// <summary>
    /// Verifies an ECDSA-SHA256 signature.
    /// </summary>
    private static bool VerifyEcdsaSha256Signature(PublicKey publicKey, byte[] tbsData, byte[] signature)
    {
        try
        {
            using ECDsa? ecdsa = publicKey.GetECDsaPublicKey();
            if (ecdsa == null)
            {
                return false;
            }
            
            return ecdsa.VerifyData(tbsData, signature, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }
    
    /// <summary>
    /// Verifies an ECDSA-SHA1 signature.
    /// </summary>
    private static bool VerifyEcdsaSha1Signature(PublicKey publicKey, byte[] tbsData, byte[] signature)
    {
        try
        {
            using ECDsa? ecdsa = publicKey.GetECDsaPublicKey();
            if (ecdsa == null)
            {
                return false;
            }
            
            return ecdsa.VerifyData(tbsData, signature, HashAlgorithmName.SHA1); // CodeQL [SM02196] This is to support certificates or other singers which use SHA1 with ECDSA for validation only.
        }
        catch
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public static new string Usage => $"{BaseUsageString}{UsageString}{GetCertificateProviderUsageString()}";

    /// <summary>
    /// Command line usage specific to the SignInternal command.
    /// Each line should have no more than 120 characters to avoid wrapping. Break is here:                            *V*
    /// </summary>
    protected new const string UsageString = @"
Sign command: Signs the specified file or piped content with a detached or embedded COSE signature.
    A detached signature resides in a separate file and validates against the original content when provided.
    An embedded signature contains a copy of the original payload. Not supported for payload of >2gb in size.

Options:
    PayloadFile / payload / p: Required, pipeable. The file or piped content to sign.

    SignatureFile / sig / sf: Optional. The file path to write the Cose signature to.
        Default value is [payload file].cose for detached signatures or [payload file].csm for embedded.
        Required if neither PayloadFile or PipeOutput are set.

    A signing certificate from one of the following sources:

        Certificate Provider Plugin (--cert-provider / -cp): Use a certificate provider plugin such as Azure
            Trusted Signing or custom HSM providers. See Certificate Providers section below for available providers.

    --OR--

        PfxCertificate / pfx: A path to a private key certificate file (.pfx) to sign with.

        Password / pw: Optional. The password for the .pfx file if it has one. (Strongly recommended!)

    --OR--

        Thumbprint / th: The SHA1 thumbprint of a certificate in the local certificate store to sign the file with.
            Use the optional StoreName and StoreLocation parameters to tell CoseSignTool where to find the matching
            certificate.

        StoreName / sn: Optional. The name of the local certificate store to find the signing certificate in.
            Default value is 'My'.

        StoreLocation / sl: Optional. The location of the local certificate store to find the signing certificate in.
            Default value is 'CurrentUser'.

    PipeOutput /po: Optional. If set, outputs the detached or embedded COSE signature to Standard Out instead of writing
        to file.

    EmbedPayload / ep: Optional. If true, embeds a copy of the payload in the COSE signature file .Content property.
        Default behavior is 'detached signing', where the COSE signature file .Content property is empty, and to validate
        the signature, the payload must be provided separately. When set to true, the payload is embedded in the signature
        file. Embed-signed files are not readable by standard text editors, but can be read with the CoseSignTool 'Get'
        command.

Advanced Options:
    ContentType /cty: Optional. A MIME type to specify as Content Type in the COSE signature header. Default value is
        'application/cose'.

    Options to enable SCITT (Supply Chain Integrity, Transparency, and Trust) compliance:
        EnableScittCompliance /scitt: Optional. If true (default), automatically adds SCITT-compliant CWT claims
            (issuer and subject) to the signature. Set to false to disable automatic CWT claims addition.

        CwtIssuer /cwt-iss: Optional. The CWT issuer (iss) claim for SCITT compliance. If not specified and SCITT
            compliance is enabled, defaults to a DID:x509 identifier derived from the signing certificate chain.

        CwtSubject /cwt-sub: Optional. The CWT subject (sub) claim for SCITT compliance. If not specified and SCITT
            compliance is enabled, defaults to ""unknown.intent"".

        CwtAudience /cwt-aud: Optional. The CWT audience (aud) claim for SCITT compliance.

        CwtClaims /cwt: Optional. Custom CWT claims as label:value pairs. Can be specified multiple times for multiple claims.
            Labels can be integers (e.g., ""100:custom-value"") or RFC 8392 claim names (iss, sub, aud, exp, nbf, iat, cti).
            Timestamp claims (exp, nbf, iat) accept date/time strings (e.g., ""2024-12-31T23:59:59Z"") or Unix timestamps.
            Examples: 
                /cwt ""cti:abc123"" /cwt ""100:custom-value"" /cwt ""exp:2024-12-31T23:59:59Z""
                /cwt ""iss:custom-issuer"" /cwt ""sub:custom-subject"" /cwt ""nbf:1735689600""

    Options to customize the headers in the signature:
        IntHeaders /ih: Optional. Path to a JSON file containing the header collection to be added to the cose message. The label is a string and the value is int32.
        Sample file. [{""label"":""created-at"",""value"":12345678,""protected"":true},{""label"":""customer-count"",""value"":10,""protected"":false}]

        StringHeaders /sh: Optional. Path to a JSON file containing the header collection to be added to the cose message. Both the label and value are strings.
        Sample file. [{""label"":""message-type"",""value"":""cose"",""protected"":false},{""label"":""customer-name"",""value"":""contoso"",""protected"":true}]

        IntProtectedHeaders /iph: A collection of name-value pairs with a string label and an int32 value. Sample input: /IntProtectedHeaders created-at=12345678,customer-count=10

        StringProtectedHeaders /sph: A collection of name-value pairs with a string label and value. Sample input: /StringProtectedHeaders message-type=cose,customer-name=contoso
    
        IntUnProtectedHeaders /iuh: A collection of name-value pairs with a string label and an int32 value. Sample input: /IntUnProtectedHeaders created-at=12345678,customer-count=10

        StringUnProtectedHeaders /suh: A collection of name-value pairs with a string label and value. Sample input: /StringUnProtectedHeaders message-type=cose,customer-name=contoso

    Options to customize file and stream handling:
        MaxWaitTime /wait: The maximum number of seconds to wait for a payload or signature file to be available and non-empty before loading it.

        FailFast /ff: If set, limits the timeout on null and empty file checks to 100ms instead of 10 seconds.

        UseAdvancedStreamHandling /adv: If set, uses experimental techniques for verifying files before attempting to read them.
";

    /// <summary>
    /// Gets the certificate provider usage documentation from loaded plugins.
    /// </summary>
    /// <returns>A formatted string containing certificate provider information, or empty string if none available.</returns>
    private static string GetCertificateProviderUsageString()
    {
        if (CoseSignTool.CertificateProviderManager.Providers.Count == 0)
        {
            return string.Empty;
        }

        StringBuilder sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine("Certificate Providers:");
        sb.AppendLine("======================");
        sb.AppendLine();
        sb.AppendLine("Available certificate provider plugins:");
        
        foreach (var kvp in CoseSignTool.CertificateProviderManager.Providers)
        {
            sb.AppendLine($"  {kvp.Key,-30} {kvp.Value.Description}");
        }
        
        sb.AppendLine();
        sb.AppendLine("To use a certificate provider, specify the --cert-provider option:");
        sb.AppendLine("  --cert-provider <provider-name>");
        sb.AppendLine("  -cp <provider-name>");
        sb.AppendLine();
        sb.AppendLine("For detailed information about a specific provider, use:");
        sb.AppendLine("  CoseSignTool help <provider-name>");
        sb.AppendLine();
        
        return sb.ToString();
    }
}
