// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

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
        ["-suh"] = "StringUnProtectedHeaders"
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

    #endregion

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
        ApplyOptions(provider);
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

        // Get the signing certificate.
        X509Certificate2 cert;
        try
        {
            cert = LoadCert();
        }
        catch (Exception ex) when (ex is CoseSign1CertificateException or FileNotFoundException or CryptographicException)
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
            // Extend the headers.
            CoseHeaderExtender? headerExtender = null;

            if (IntHeaders != null ||
                StringHeaders != null)
            {
                headerExtender = new();
            }

            if (IntHeaders != null && IntHeaders.Count > 0)
            {
                CoseHandler.HeaderFactory.AddProtectedHeaders<int>(IntHeaders.ToList().Where(h => h.IsProtected));
                CoseHandler.HeaderFactory.AddUnProtectedHeaders<int>(IntHeaders.ToList().Where(h => !h.IsProtected));
            }

            if(StringHeaders != null && StringHeaders.Count > 0)
            {
                CoseHandler.HeaderFactory.AddProtectedHeaders<string>(StringHeaders.ToList().Where(h => h.IsProtected));
                CoseHandler.HeaderFactory.AddUnProtectedHeaders<string>(StringHeaders.ToList().Where(h => !h.IsProtected));
            }

            // Sign the content.
            ReadOnlyMemory<byte> signedBytes = CoseHandler.Sign(payloadStream, cert, EmbedPayload, SignatureFile, ContentType ?? CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE, headerExtender);

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

        base.ApplyOptions(provider);
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
    /// <returns>The certificate if found.</returns>
    /// <exception cref="ArgumentOutOfRangeException">User passed in a thumbprint instead of a file path on a non-Windows OS.</exception>
    /// <exception cref="ArgumentNullException">No certificate filepath or thumbprint was given.</exception>
    /// <exception cref="CryptographicException">The certificate was found but could not be loaded
    /// -- OR --
    /// The certificate required a password and the user did not supply one, or the user-supplied password was wrong.</exception>
    internal X509Certificate2 LoadCert()
    {
        X509Certificate2 cert;
        if (PfxCertificate is not null)
        {
            // Load the PFX certificate. This will throw a CryptographicException if the password is wrong or missing.
            ThrowIfMissing(PfxCertificate, "Could not find the certificate file");
            cert = new X509Certificate2(PfxCertificate, Password);
        }
        else
        {
            // Load certificate from thumbprint.
            cert = Thumbprint is not null ? CoseHandler.LookupCertificate(Thumbprint, StoreName!, StoreLocation) :
                throw new ArgumentNullException("You must specify a certificate file or thumbprint to sign with.");
        }

        return cert;
    }

    /// <inheritdoc/>
    public static new string Usage => $"{BaseUsageString}{UsageString}";

    /// <summary>
    /// Command line usage specific to the SignInternal command.
    /// Each line should have no more than 120 characters to avoid wrapping. Break is here:                            *V*
    /// </summary>
    protected new const string UsageString = @"
Sign command: Signs the specified file or piped content with a detached or embedded signature.
    A detached signature resides in a separate file and validates against the original content by hash match.
    An embedded signature contains an encoded copy of the original payload. Not supported for payload of >2gb in size.

Options:
    PayloadFile / payload / p: Required, pipeable. The file or piped content to sign.

    SignatureFile / sig / sf: Optional. The file path to write the Cose signature to.
        Default value is [payload file].cose for detached signatures or [payload file].csm for embedded.
        Required if neither PayloadFile or PipeOutput are set.

    A signing certificate as either:

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

    EmbedPayload / ep: Optional. If true, encrypts and embeds a copy of the payload in the in COSE signature file.
        Default behavior is 'detached signing', where the signature is in a separate file from the payload.
        Embed-signed files are not readable by standard text editors, but can be read with the CoseSignTool 'Get'
        command.

    ContentType /cty: Optional. A MIME type to specify as Content Type in the COSE signature header. Default value is
        'application/cose'.

    IntHeaders /ih: Optional. Path to a JSON file containing the header collection to be added to the cose message. The label is a string and the value is int32.
    Sample file. [{""label"":""created-at"",""value"":12345678,""protected"":true},{""label"":""customer-count"",""value"":10,""protected"":false}]

    StringHeaders /sh: Optional. Path to a JSON file containing the header collection to be added to the cose message. Both the label and value are strings.
    Sample file. [{""label"":""message-type"",""value"":""cose"",""protected"":false},{""label"":""customer-name"",""value"":""contoso"",""protected"":true}]

    IntProtectedHeders /iph: A collection of name-value pairs with a string label and an int32 value. Sample input: /IntProtectedHeaders created-at=12345678,customer-count=10

    StringProtectedHeders /sph: A collection of name-value pairs with a string label and value. Sample input: /StringProtectedHeaders message-type=cose,customer-name=contoso
    
    IntUnProtectedHeders /iuh: A collection of name-value pairs with a string label and an int32 value. Sample input: /IntUnProtectedHeaders created-at=12345678,customer-count=10

    StringUnProtectedHeders /suh: A collection of name-value pairs with a string label and value. Sample input: /StringUnProtectedHeaders message-type=cose,customer-name=contoso
";
}
