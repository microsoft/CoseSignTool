// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;
public class ValidateCommand : CoseCommand
{
    /// <summary>
    /// Map of command line options specific to the Validate command and their abbreviated aliases.
    /// </summary>
    private static readonly Dictionary<string, string> PrivateOptions = new()
    {
        ["-Roots"] = "Roots",
        ["-rt"] = "Roots",
        ["-RevocationMode"] = "RevocationMode",
        ["-revmode"] = "RevocationMode",
        ["-rm"] = "RevocationMode",
        ["-CommonName"] = "CommonName",
        ["-cn"] = "CommonName",
        ["-AllowUntrusted"] = "AllowUntrusted",
        ["-allow"] = "AllowUntrusted",
        ["-au"] = "AllowUntrusted",
        ["-ShowCertificateDetails"] = "ShowCertificateDetails",
        ["-scd"] = "ShowCertificateDetails",
        ["-Verbose"] = "Verbose",
        ["-v"] = "Verbose",
    };

    /// <summary>
    /// Map of COSE validation failure codes to CoseSignTool exit codes.
    /// </summary>
    private static readonly Dictionary<ValidationFailureCode, ExitCode> ErrorMap = new()
    {
        { ValidationFailureCode.CertificateChainUnreadable, ExitCode.CertificateLoadFailure },
        { ValidationFailureCode.CoseHeadersInvalid, ExitCode.SignatureLoadError },
        { ValidationFailureCode.NoPrivateKey, ExitCode.CertificateLoadFailure },
        { ValidationFailureCode.NoPublicKey, ExitCode.CertificateLoadFailure },
        { ValidationFailureCode.PayloadMismatch, ExitCode.PayloadValidationError },
        { ValidationFailureCode.PayloadMissing, ExitCode.PayloadReadError },
        { ValidationFailureCode.PayloadUnreadable, ExitCode.PayloadReadError },
        { ValidationFailureCode.RedundantPayload, ExitCode.PayloadValidationError },
        { ValidationFailureCode.SigningCertificateUnreadable, ExitCode.CertificateLoadFailure },
        { ValidationFailureCode.CertificateChainInvalid, ExitCode.CertificateChainValidationFailure },
        { ValidationFailureCode.TrustValidationFailed, ExitCode.TrustValidationFailure },
        { ValidationFailureCode.Unknown, ExitCode.UnknownError },
    };

    //<inheritdoc />
    public static new readonly Dictionary<string, string> Options =
        CoseCommand.Options.Concat(PrivateOptions).ToDictionary(k => k.Key, k => k.Value);

    #region Public properties
    /// <summary>
    /// Gets or sets one or more certificate files (.cer or .p7b) to attempt to chain the COSE signature to.
    /// These certificates do not have to be trusted on the local machine.
    /// </summary>
    [DefaultValue(null)]
    public string[]? Roots { get; set; }

    /// <summary>
    /// Gets or sets the revocation mode to use when checking for expired or revoked certificates.
    /// Default is X509RevocationMode.Online.
    /// </summary>
    public X509RevocationMode RevocationMode { get; set; }

    /// <summary>
    /// Requires that the signing certificate must match a specific Certificate Common Name.
    /// </summary>
    [DefaultValue(null)]
    public string? CommonName { get; set; }

    /// <summary>
    /// Allows certificates without trusted roots to pass validation.
    /// </summary>
    public bool AllowUntrusted { get; set; }

    public bool ShowCertificateDetails { get; set; }

    /// <summary>
    /// True to print more details to console on validation failures.
    /// </summary>
    public bool Verbose { get; set; }
    #endregion

    /// <summary>
    /// For test use only.
    /// </summary>
    internal ValidateCommand() { }

    /// <summary>
    /// Creates a ValidateCommand instance and sets its properties with a CommandLineConfigurationProvider.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider that has loaded the command line arguments.</param>
    public ValidateCommand(CommandLineConfigurationProvider provider)
    {
        ApplyOptions(provider);
    }

    /// <summary>
    /// Validates a Cose signed file.
    /// </summary>
    /// <returns>An exit code indicating success or failure.</returns>
    public override ExitCode Run()
    {
        // Get the signature, either piped in or from file.
        Stream signatureStream = GetStreamFromPipeOrFile(SignatureFile, nameof(SignatureFile));

        // Make sure the external payload file is present if specified.
        if (PayloadFile is not null && !PayloadFile.Exists)
        {
            return CoseSignTool.Fail(
                ExitCode.PayloadReadError,
                new FileNotFoundException(nameof(PayloadFile)),
                $"Could not find the external Payload file at {PayloadFile}.");
        }

        // Get the root certs from file if any.
        List<X509Certificate2>? rootCerts;
        try
        {
            rootCerts = LoadRootCerts(Roots);
        }
        catch (Exception ex) when (ex is FileNotFoundException or ArgumentOutOfRangeException or CryptographicException)
        {
            return CoseSignTool.Fail(ExitCode.CertificateLoadFailure, ex, "Could not load root certificates");
        }

        // Run the validation and catch any expected exceptions.
        try
        {
            ValidationResult result = RunCoseHandlerCommand(
                signatureStream,
                PayloadFile,
                rootCerts,
                RevocationMode,
                CommonName,
                AllowUntrusted);

            // Write the result to console on STDOUT
            Console.WriteLine(result.ToString(Verbose, ShowCertificateDetails));

            return result.Success ? ExitCode.Success
                : result.Errors?.Count > 0 ? ErrorMap[result.Errors.FirstOrDefault().ErrorCode]
                : ExitCode.UnknownError;
        }
        catch (ArgumentException ex)
        {
            // The user passed in an empty payload or specified payload in two places.
            return CoseSignTool.Fail(ExitCode.PayloadReadError, ex);
        }
        catch (Exception ex) when (ex is CryptographicException)
        {
            // There is an error in the signing certificate.
            return CoseSignTool.Fail(ExitCode.CertificateLoadFailure, ex);
        }
        catch (CoseX509FormatException ex)
        {
            // There is an error in the COSE headers.
            return CoseSignTool.Fail(ExitCode.SignatureLoadError, ex);
        }
    }

    // A pass-through method to let derived classes modify the command and otherwise re-use the surrounding code.
    protected internal virtual ValidationResult RunCoseHandlerCommand(
        Stream signature,
        FileInfo? payload,
        List<X509Certificate2>? rootCerts,
        X509RevocationMode revocationMode,
        string? commonName,
        bool allowUntrusted)
        => CoseHandler.Validate(
            signature,
            payload?.OpenRead(),
            rootCerts,
            revocationMode,
            commonName,
            allowUntrusted);

    //<inheritdoc />
    protected internal override void ApplyOptions(CommandLineConfigurationProvider provider)
    {
        Roots = GetOptionArray(provider, nameof(Roots));
        string revModeString = GetOptionString(provider, nameof(RevocationMode), "online");
        RevocationMode = Enum.Parse<X509RevocationMode>(revModeString, true);
        CommonName = GetOptionString(provider, nameof(CommonName));
        AllowUntrusted = GetOptionBool(provider, nameof(AllowUntrusted));
        ShowCertificateDetails = GetOptionBool(provider, nameof(ShowCertificateDetails));
        Verbose = GetOptionBool(provider, nameof(Verbose));
        base.ApplyOptions(provider);
    }

    // Load public key certificates from file
    protected static List<X509Certificate2>? LoadRootCerts(string[]? X509RootFiles)
    {
        if (X509RootFiles is null)
        {
            return null;
        }

        List<X509Certificate2> rootCerts = new();
        foreach (string rootFile in X509RootFiles)
        {
            ThrowIfMissing(rootFile, $"Could not find root certificate at {rootFile}");

            switch (Path.GetExtension(rootFile).ToLowerInvariant())
            {
                case ".p7b":
                    X509Certificate2Collection certCollection = new();
                    certCollection.Import(rootFile);
                    rootCerts.AddRange(certCollection);
                    break;
                case ".cer":
                    rootCerts.Add(new X509Certificate2(rootFile));
                    break;
                default:
                    throw new ArgumentOutOfRangeException($"Unsupported certificate file type {rootFile}");
            }
        }

        return rootCerts;
    }

    /// <inheritdoc/>
    public static new string Usage => $"{BaseUsageString}{UsageString}{SharedOptionsText}";

    // The usage text to display. Each line should have no more than 120 characters to avoid wrapping. Break is here:  *V*
    protected new const string UsageString = @"
Validate command: Validates that the specified COSE signature file or piped signature content matches the original
    payload and is signed with a valid certificate chain.

Options:

    SignatureFile / sigfile / sf: Required, pipeable. The file or piped stream containing the COSE signature.

    PayloadFile / payload / p: Required for detached signatures. The original source file that was signed.
        Do not use for embedded signatures.
";

    protected const string SharedOptionsText = $@"
    Roots / rt: Optional. A comma-separated list of public key certificate files (.cer or .p7b), enclosed in quote
        marks, to try to chain the signing certificate to.
        CoseSignTool will try to chain to installed roots first, then user-supplied roots.
        If the COSE signature is signed with a self-signed certificate, that certificate must either be installed on and
        trusted by the machine or supplied as a root to pass validation.
        All user-supplied roots are assumed to be trusted for validation purposes.

    RevocationMode / revmode / rm: Optional. The method to check for certificate revocation.
        Valid values: Online, Offline, NoCheck
        Default value: Online

    CommonName / cn: Optional. Specifies a Certificate Common Name that the signing certificate must match to pass
        validation.

    AllowUntrusted / allow / au: Optional flag. Allows validation to succeed when chaining to an arbitrary root
        certificate on the host machine without that root being trusted.

    ShowCertificateDetails / scd: Optional flag. Prints the certificate chain details to the console if the certificate chain is available.

    Verbose / v: Optional flag. Includes certificate chain status errors and exception messages in the error output
        when validation fails.";
}
