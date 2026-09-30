// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias IdentityAlias;

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using Azure;
using Azure.ArtifactSigning.MST;
using Azure.Core;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text.Json;
using AuthenticationFailedException = IdentityAlias::Azure.Identity.AuthenticationFailedException;

/// <summary>
/// Registers a COSE Sign1 message with MST through the Azure Artifact Signing proxy.
/// </summary>
public sealed class AzureArtifactSigningMstRegisterCommand : PluginCommandBase
{
    private static readonly Dictionary<string, string> CommandOptions = new()
    {
        ["endpoint"] = "The Microsoft Signing Transparency ledger endpoint URL",
        ["proxy-endpoint"] = "The Azure Artifact Signing proxy endpoint URL",
        ["account-name"] = "The Azure Artifact Signing account name",
        ["cert-profile-name"] = "The Azure Artifact Signing certificate profile name",
        ["payload"] = "The file path to the payload file",
        ["signature"] = "The file path to the COSE Sign1 signature file",
        ["output"] = "The file path where the result will be written (optional)",
        ["timeout"] = "Timeout in seconds (default: 30)",
        ["correlation-id"] = "The correlation ID sent to Azure Artifact Signing (optional)",
        [AzureCredentialFactory.ExcludeCredentialsKey] = "Comma-separated credentials to exclude from DefaultAzureCredential"
    };

    private readonly Func<Uri, IConfiguration, IPluginLogger, TransparencyClient> transparencyClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureArtifactSigningMstRegisterCommand"/> class.
    /// </summary>
    public AzureArtifactSigningMstRegisterCommand()
        : this(CreateTransparencyClient)
    {
    }

    internal AzureArtifactSigningMstRegisterCommand(
        Func<Uri, IConfiguration, IPluginLogger, TransparencyClient> transparencyClientFactory)
    {
        this.transparencyClientFactory = transparencyClientFactory
            ?? throw new ArgumentNullException(nameof(transparencyClientFactory));
    }

    /// <inheritdoc/>
    public override string Name => "aas_mst_register";

    /// <inheritdoc/>
    public override string Description => "Register a COSE Sign1 message with MST through Azure Artifact Signing";

    /// <inheritdoc/>
    public override string Usage =>
        $"CoseSignTool {Name} --endpoint <mst-endpoint> --proxy-endpoint <aas-endpoint> --account-name <account> --cert-profile-name <profile> --payload <payload-file> --signature <signature-file> [options]{Environment.NewLine}" +
        $"{Environment.NewLine}" +
        $"Required arguments:{Environment.NewLine}" +
        $"  --endpoint                Microsoft Signing Transparency ledger endpoint URL{Environment.NewLine}" +
        $"  --proxy-endpoint          Azure Artifact Signing proxy endpoint URL{Environment.NewLine}" +
        $"  --account-name            Azure Artifact Signing account name{Environment.NewLine}" +
        $"  --cert-profile-name       Azure Artifact Signing certificate profile name{Environment.NewLine}" +
        $"  --payload                 Payload file path{Environment.NewLine}" +
        $"  --signature               COSE Sign1 signature file path{Environment.NewLine}" +
        $"{Environment.NewLine}" +
        $"Optional arguments:{Environment.NewLine}" +
        $"  --output                  JSON result output path{Environment.NewLine}" +
        $"  --timeout                 Timeout in seconds (default: 30){Environment.NewLine}" +
        $"  --correlation-id          Correlation ID sent to Azure Artifact Signing{Environment.NewLine}" +
        $"  --aas-exclude-credentials Comma-separated credentials to exclude from DefaultAzureCredential{Environment.NewLine}";

    /// <inheritdoc/>
    public override IDictionary<string, string> Options => CommandOptions;

    /// <inheritdoc/>
    public override async Task<PluginExitCode> ExecuteAsync(
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        try
        {
            string ledgerEndpoint = GetRequiredNonWhitespaceValue(configuration, "endpoint");
            string proxyEndpoint = GetRequiredNonWhitespaceValue(configuration, "proxy-endpoint");
            string accountName = GetRequiredNonWhitespaceValue(configuration, "account-name");
            string certificateProfileName = GetRequiredNonWhitespaceValue(configuration, "cert-profile-name");
            string payloadPath = GetRequiredNonWhitespaceValue(configuration, "payload");
            string signaturePath = GetRequiredNonWhitespaceValue(configuration, "signature");
            string? outputPath = GetOptionalValue(configuration, "output");
            string? correlationId = GetOptionalValue(configuration, "correlation-id");

            if (!TryCreateHttpsEndpoint(ledgerEndpoint, out Uri? ledgerEndpointUri))
            {
                Logger.LogError("The Microsoft Signing Transparency endpoint must be an absolute HTTPS URL.");
                return PluginExitCode.InvalidArgumentValue;
            }

            if (!TryCreateHttpsEndpoint(proxyEndpoint, out Uri? proxyEndpointUri))
            {
                Logger.LogError("The Azure Artifact Signing proxy endpoint must be an absolute HTTPS URL.");
                return PluginExitCode.InvalidArgumentValue;
            }

            if (!TryGetTimeout(configuration, out int timeoutSeconds))
            {
                Logger.LogError("Invalid timeout value. Must be a positive integer.");
                return PluginExitCode.InvalidArgumentValue;
            }

            if (!File.Exists(payloadPath))
            {
                Logger.LogError($"Payload file not found: {payloadPath}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            if (!File.Exists(signaturePath))
            {
                Logger.LogError($"Signature file not found: {signaturePath}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            byte[] signatureBytes = await File.ReadAllBytesAsync(signaturePath, cancellationToken).ConfigureAwait(false);
            CoseMessage.DecodeSign1(signatureBytes);

            Logger.LogInformation("Registering COSE Sign1 message with MST through Azure Artifact Signing...");
            Logger.LogVerbose($"  Ledger endpoint: {ledgerEndpointUri}");
            Logger.LogVerbose($"  Proxy endpoint: {proxyEndpointUri}");
            Logger.LogVerbose($"  Account: {accountName}");
            Logger.LogVerbose($"  Certificate profile: {certificateProfileName}");
            Logger.LogVerbose($"  Payload: {payloadPath}");
            Logger.LogVerbose($"  Signature: {signaturePath} ({signatureBytes.Length} bytes)");

            using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(timeoutSeconds));
            using CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                timeoutCts.Token);
            using MemoryStream signatureStream = new(signatureBytes, writable: false);

            TransparencyClient transparencyClient = this.transparencyClientFactory(
                proxyEndpointUri,
                configuration,
                Logger);
            string mstInstanceName = ledgerEndpointUri.Host.Split('.')[0];
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

            Logger.LogInformation("Registration through Azure Artifact Signing completed successfully.");

            if (!string.IsNullOrWhiteSpace(outputPath))
            {
                object result = new
                {
                    Endpoint = ledgerEndpointUri.ToString(),
                    ProxyEndpoint = proxyEndpointUri.ToString(),
                    AccountName = accountName,
                    CertificateProfileName = certificateProfileName,
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    RegistrationTime = DateTime.UtcNow,
                    TransparencyReceipt = Convert.ToBase64String(receipt)
                };

                string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(outputPath, json, linkedCts.Token).ConfigureAwait(false);
                Logger.LogInformation($"Result written to: {outputPath}");
            }

            return PluginExitCode.Success;
        }
        catch (ArgumentNullException ex)
        {
            Logger.LogError($"Missing required argument - {ex.ParamName}");
            return PluginExitCode.MissingRequiredOption;
        }
        catch (ArgumentException ex)
        {
            Logger.LogError(ex.Message);
            return PluginExitCode.InvalidArgumentValue;
        }
        catch (CryptographicException ex)
        {
            Logger.LogError($"Failed to decode the COSE Sign1 signature: {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.InvalidArgumentValue;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Logger.LogError("Operation was cancelled.");
            return PluginExitCode.UnknownError;
        }
        catch (OperationCanceledException)
        {
            Logger.LogError($"Operation timed out after {GetOptionalValue(configuration, "timeout", "30")} seconds.");
            return PluginExitCode.UnknownError;
        }
        catch (RequestFailedException ex)
        {
            Logger.LogError($"Azure Artifact Signing rejected the transparency registration: HTTP {ex.Status}, {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (AuthenticationFailedException ex)
        {
            Logger.LogError($"Failed to authenticate to Azure Artifact Signing: {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (UnauthorizedAccessException ex)
        {
            Logger.LogError($"File access failed: {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (IOException ex)
        {
            Logger.LogError($"File operation failed: {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
    }

    internal static bool TryCreateHttpsEndpoint(string value, out Uri? endpoint)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out endpoint)
            && string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    private static TransparencyClient CreateTransparencyClient(
        Uri endpoint,
        IConfiguration configuration,
        IPluginLogger logger)
    {
        TokenCredential credential = AzureCredentialFactory.GetCredential(
            AzureCredentialFactory.GetExclusions(configuration),
            logger);
        return new TransparencyClient(credential, endpoint);
    }

    private static string GetRequiredNonWhitespaceValue(IConfiguration configuration, string key)
    {
        string value = GetRequiredValue(configuration, key);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"Required configuration value '{key}' cannot be empty.", key);
        }

        return value;
    }

    private static bool TryGetTimeout(IConfiguration configuration, out int timeoutSeconds)
    {
        return int.TryParse(GetOptionalValue(configuration, "timeout", "30"), out timeoutSeconds)
            && timeoutSeconds > 0;
    }
}
