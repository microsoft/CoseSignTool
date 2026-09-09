// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias IdentityAlias;

namespace CoseSignTool.MST.Plugin;

using System.Security.Cryptography.Cose;
using Azure;
using Azure.ArtifactSigning.MST;
using AuthenticationFailedException = IdentityAlias::Azure.Identity.AuthenticationFailedException;
using DefaultAzureCredential = IdentityAlias::Azure.Identity.DefaultAzureCredential;
using DefaultAzureCredentialOptions = IdentityAlias::Azure.Identity.DefaultAzureCredentialOptions;

/// <summary>
/// Command to register a COSE Sign1 message with Microsoft's Signing Transparency (MST).
/// </summary>
public class RegisterCommand : MstCommandBase
{
    private static readonly Dictionary<string, string> RegisterOptions = new(CommonOptions)
    {
        { "proxy-endpoint", "The Azure Artifact Signing proxy endpoint URL (optional)" },
        { "account-name", "The Azure Artifact Signing account name used for proxy authorization" },
        { "cert-profile-name", "The Azure Artifact Signing certificate profile name used for proxy authorization" },
        { "correlation-id", "The correlation ID sent to Azure Artifact Signing (optional)" },
        { "aas-exclude-credentials", "Comma-separated credentials to exclude from DefaultAzureCredential" }
    };

    private static readonly IReadOnlyDictionary<string, Action<DefaultAzureCredentialOptions>> CredentialExclusions =
        new Dictionary<string, Action<DefaultAzureCredentialOptions>>(StringComparer.OrdinalIgnoreCase)
        {
            ["Environment"] = options => options.ExcludeEnvironmentCredential = true,
            ["WorkloadIdentity"] = options => options.ExcludeWorkloadIdentityCredential = true,
            ["ManagedIdentity"] = options => options.ExcludeManagedIdentityCredential = true,
            ["AzureDeveloperCli"] = options => options.ExcludeAzureDeveloperCliCredential = true,
#pragma warning disable CS0618 // SharedTokenCacheCredential is deprecated but remains a valid exclusion.
            ["SharedTokenCache"] = options => options.ExcludeSharedTokenCacheCredential = true,
#pragma warning restore CS0618
            ["InteractiveBrowser"] = options => options.ExcludeInteractiveBrowserCredential = true,
            ["Broker"] = options => options.ExcludeBrokerCredential = true,
            ["AzureCli"] = options => options.ExcludeAzureCliCredential = true,
            ["VisualStudio"] = options => options.ExcludeVisualStudioCredential = true,
            ["VisualStudioCode"] = options => options.ExcludeVisualStudioCodeCredential = true,
            ["AzurePowerShell"] = options => options.ExcludeAzurePowerShellCredential = true,
        };

    private readonly Func<Uri, IConfiguration, TransparencyClient> transparencyClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="RegisterCommand"/> class.
    /// </summary>
    public RegisterCommand()
        : this(CreateTransparencyClient)
    {
    }

    internal RegisterCommand(Func<Uri, IConfiguration, TransparencyClient> transparencyClientFactory)
    {
        this.transparencyClientFactory = transparencyClientFactory
            ?? throw new ArgumentNullException(nameof(transparencyClientFactory));
    }

    /// <inheritdoc/>
    public override string Name => "mst_register";

    /// <inheritdoc/>
    public override string Description => "Register a COSE Sign1 message with Microsoft's Signing Transparency (MST)";

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage(Name, "register") +
        $"  --timeout           Timeout in seconds (default: 30){Environment.NewLine}" +
        $"  --proxy-endpoint    Register through the Azure Artifact Signing proxy instead of calling the ledger directly{Environment.NewLine}" +
        $"  --account-name      Azure Artifact Signing account name; required with --proxy-endpoint{Environment.NewLine}" +
        $"  --cert-profile-name Azure Artifact Signing certificate profile; required with --proxy-endpoint{Environment.NewLine}" +
        $"  --correlation-id    Correlation ID sent to Azure Artifact Signing (optional){Environment.NewLine}" +
        $"  --aas-exclude-credentials Comma-separated credentials to exclude from DefaultAzureCredential{Environment.NewLine}" +
        $"{Environment.NewLine}" +
        $"Examples:{Environment.NewLine}" +
        GetExamples();

    /// <inheritdoc/>
    public override IDictionary<string, string> Options => RegisterOptions;

    /// <inheritdoc/>
    public override Task<PluginExitCode> ExecuteAsync(
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        string? proxyEndpoint = GetOptionalValue(configuration, "proxy-endpoint");
        if (string.IsNullOrWhiteSpace(proxyEndpoint))
        {
            return base.ExecuteAsync(configuration, cancellationToken);
        }

        return this.ExecuteProxyRegistrationAsync(configuration, proxyEndpoint, cancellationToken);
    }

    /// <inheritdoc/>
    protected override string GetExamples()
    {
        return $"  CoseSignTool mst_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose{Environment.NewLine}" +
               $"  CoseSignTool mst_register --endpoint https://debugruisuprivatetrust.confidential-ledger.azure.com --proxy-endpoint https://api-canary.northcentralus.codesigning.azure.net/ --account-name MyAccount --cert-profile-name MyProfile --payload sample_payload.txt --signature sample_payload.cose{Environment.NewLine}" +
               $"  CoseSignTool mst_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --output result.json{Environment.NewLine}" +
               $"  CoseSignTool mst_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --token-env MY_TOKEN_VAR";
    }

    /// <inheritdoc/>
    protected override async Task<(PluginExitCode exitCode, object? result)> ExecuteSpecificOperation(
        CodeTransparencyClient client,
        CoseSign1Message message,
        byte[] signatureBytes,
        string endpoint,
        string payloadPath,
        string signaturePath,
        IConfiguration configuration,
        CancellationToken cancellationToken)
    {
        this.Logger.LogVerbose("Creating transparency service");
        CoseSign1.Transparent.MST.MstPollingOptions pollingOptions = new()
        {
            PollingInterval = TimeSpan.FromMilliseconds(DefaultPollingIntervalMs)
        };
        CoseSign1.Transparent.TransparencyService transparencyService = client.ToCoseSign1TransparencyService(
            pollingOptions,
            logVerbose: this.Logger.LogVerbose,
            logWarning: this.Logger.LogWarning,
            logError: this.Logger.LogError);

        this.PrintOperationStatus("Registering", endpoint, payloadPath, signaturePath, signatureBytes.Length);

        this.Logger.LogVerbose("Calling MakeTransparentAsync...");
        CoseSign1Message result = await transparencyService.MakeTransparentAsync(message, cancellationToken).ConfigureAwait(false);

        this.Logger.LogInformation("Registration completed successfully.");

        object jsonResult = new
        {
            Endpoint = endpoint,
            PayloadPath = payloadPath,
            SignaturePath = signaturePath,
            RegistrationTime = DateTime.UtcNow,
            TransparentMessage = Convert.ToBase64String(result.Encode())
        };

        return (PluginExitCode.Success, jsonResult);
    }

    private async Task<PluginExitCode> ExecuteProxyRegistrationAsync(
        IConfiguration configuration,
        string proxyEndpoint,
        CancellationToken cancellationToken)
    {
        try
        {
            string ledgerEndpoint = GetRequiredValue(configuration, "endpoint");
            string accountName = GetRequiredValue(configuration, "account-name");
            string certificateProfileName = GetRequiredValue(configuration, "cert-profile-name");
            string payloadPath = GetRequiredValue(configuration, "payload");
            string signaturePath = GetRequiredValue(configuration, "signature");
            string? outputPath = GetOptionalValue(configuration, "output");
            string? correlationId = GetOptionalValue(configuration, "correlation-id");

            if (!TryCreateProxyEndpoint(proxyEndpoint, out Uri? proxyEndpointUri))
            {
                this.Logger.LogError("The Azure Artifact Signing proxy endpoint must be an absolute HTTPS URL.");
                return PluginExitCode.InvalidArgumentValue;
            }

            PluginExitCode validationResult = ValidateCommonParameters(
                configuration,
                out int timeoutSeconds,
                this.Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            validationResult = ValidateFilePaths(
                new Dictionary<string, string>
                {
                    { "Payload", payloadPath },
                    { "Signature", signaturePath }
                },
                this.Logger);
            if (validationResult != PluginExitCode.Success)
            {
                return validationResult;
            }

            (CoseSign1Message? _, byte[] signatureBytes, PluginExitCode readResult) =
                await ReadAndDecodeCoseMessage(signaturePath, cancellationToken, this.Logger).ConfigureAwait(false);
            if (readResult != PluginExitCode.Success)
            {
                return readResult;
            }

            this.Logger.LogInformation("Registering COSE Sign1 message with MST through Azure Artifact Signing...");
            this.Logger.LogVerbose($"  Ledger endpoint: {ledgerEndpoint}");
            this.Logger.LogVerbose($"  Proxy endpoint: {proxyEndpointUri}");
            this.Logger.LogVerbose($"  Account: {accountName}");
            this.Logger.LogVerbose($"  Certificate profile: {certificateProfileName}");
            this.Logger.LogVerbose($"  Payload: {payloadPath}");
            this.Logger.LogVerbose($"  Signature: {signaturePath} ({signatureBytes.Length} bytes)");

            using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(timeoutSeconds));
            using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                timeoutCts.Token);
            using MemoryStream signatureStream = new(signatureBytes, writable: false);

            TransparencyClient transparencyClient = this.transparencyClientFactory(proxyEndpointUri, configuration);
            string mstInstanceName = new Uri(ledgerEndpoint).Host.Split('.')[0];
            Response<Stream> response = await transparencyClient.RegisterTransparencyAsync(
                accountName,
                certificateProfileName,
                mstInstanceName,
                signatureStream,
                correlationId,
                linkedCts.Token).ConfigureAwait(false);

            await using Stream receiptStream = response.Value;
            using MemoryStream receiptBuffer = new();
            await receiptStream.CopyToAsync(receiptBuffer, linkedCts.Token).ConfigureAwait(false);
            byte[] receipt = receiptBuffer.ToArray();

            this.Logger.LogInformation("Registration through Azure Artifact Signing completed successfully.");

            if (!string.IsNullOrWhiteSpace(outputPath))
            {
                object result = new
                {
                    Endpoint = ledgerEndpoint,
                    ProxyEndpoint = proxyEndpointUri.ToString(),
                    AccountName = accountName,
                    CertificateProfileName = certificateProfileName,
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    RegistrationTime = DateTime.UtcNow,
                    TransparencyReceipt = Convert.ToBase64String(receipt)
                };

                await WriteJsonResult(outputPath, result, linkedCts.Token, this.Logger).ConfigureAwait(false);
            }

            return PluginExitCode.Success;
        }
        catch (ArgumentNullException ex)
        {
            this.Logger.LogError($"Missing required argument - {ex.ParamName}");
            return PluginExitCode.MissingRequiredOption;
        }
        catch (ArgumentException ex)
        {
            this.Logger.LogError(ex.Message);
            return PluginExitCode.InvalidArgumentValue;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            this.Logger.LogError("Operation was cancelled.");
            return PluginExitCode.UnknownError;
        }
        catch (OperationCanceledException)
        {
            this.Logger.LogError($"Operation timed out after {GetOptionalValue(configuration, "timeout", "30")} seconds.");
            return PluginExitCode.UnknownError;
        }
        catch (RequestFailedException ex)
        {
            this.Logger.LogError($"Azure Artifact Signing rejected the transparency registration: HTTP {ex.Status}, {ex.Message}");
            this.Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (AuthenticationFailedException ex)
        {
            this.Logger.LogError($"Failed to authenticate to Azure Artifact Signing: {ex.Message}");
            this.Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (IOException ex)
        {
            this.Logger.LogError($"File operation failed: {ex.Message}");
            this.Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
    }

    internal static bool TryCreateProxyEndpoint(string value, out Uri? endpoint)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out endpoint)
            && string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    internal static DefaultAzureCredentialOptions CreateCredentialOptions(IConfiguration configuration)
    {
        DefaultAzureCredentialOptions credentialOptions = new()
        {
            ExcludeInteractiveBrowserCredential = true
        };

        string? configuredExclusions = configuration["aas-exclude-credentials"];
        if (string.IsNullOrWhiteSpace(configuredExclusions))
        {
            return credentialOptions;
        }

        foreach (string exclusion in configuredExclusions.Split(
            ',',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string credentialName = exclusion.EndsWith("Credential", StringComparison.OrdinalIgnoreCase)
                ? exclusion[..^"Credential".Length]
                : exclusion;

            if (!CredentialExclusions.TryGetValue(credentialName, out Action<DefaultAzureCredentialOptions>? applyExclusion))
            {
                IEnumerable<string> supportedNames = CredentialExclusions.Keys
                    .Select(name => name + "Credential")
                    .OrderBy(name => name, StringComparer.Ordinal);
                throw new ArgumentException(
                    $"'{exclusion}' is not a recognized credential to exclude. Supported values are: {string.Join(", ", supportedNames)}.",
                    "aas-exclude-credentials");
            }

            applyExclusion(credentialOptions);
        }

        return credentialOptions;
    }

    private static TransparencyClient CreateTransparencyClient(Uri endpoint, IConfiguration configuration)
    {
        DefaultAzureCredentialOptions credentialOptions = CreateCredentialOptions(configuration);
        DefaultAzureCredential credential = new(credentialOptions); // CodeQL [SM02196] DefaultAzureCredential is the recommended credential for client applications.
        return new TransparencyClient(credential, endpoint);
    }
}
