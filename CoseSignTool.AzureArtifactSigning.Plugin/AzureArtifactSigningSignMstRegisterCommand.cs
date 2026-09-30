// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Azure.Core 1.60.0 introduced its own AuthenticationFailedException, which collides with the
// Azure.Identity type. Alias Azure.Identity so the command catches the credential-chain exception.
extern alias IdentityAlias;

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using Azure;
using Azure.ArtifactSigning.MST;
using Azure.Core;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using AuthenticationFailedException = IdentityAlias::Azure.Identity.AuthenticationFailedException;

/// <summary>
/// Signs a payload with Azure Artifact Signing and registers the generated COSE Sign1 statement
/// with Microsoft Signing Transparency through the Azure Artifact Signing proxy.
/// </summary>
public sealed class AzureArtifactSigningSignMstRegisterCommand : PluginCommandBase, IGenericSignPluginCommand
{
    private readonly Func<Uri, IConfiguration, IPluginLogger, TransparencyClient> transparencyClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureArtifactSigningSignMstRegisterCommand"/> class.
    /// </summary>
    public AzureArtifactSigningSignMstRegisterCommand()
        : this(CreateTransparencyClient)
    {
    }

    internal AzureArtifactSigningSignMstRegisterCommand(
        Func<Uri, IConfiguration, IPluginLogger, TransparencyClient> transparencyClientFactory)
    {
        this.transparencyClientFactory = transparencyClientFactory
            ?? throw new ArgumentNullException(nameof(transparencyClientFactory));
    }

    /// <inheritdoc/>
    public override string Name => "aas_sign_mst_register";

    /// <inheritdoc/>
    public override string Description =>
        "Signs a payload with Azure Artifact Signing and registers the generated COSE statement with MST.";

    /// <inheritdoc/>
    public override string Usage =>
        "CoseSignTool aas_sign_mst_register --endpoint <mst-ledger-url> --proxy-endpoint <aas-proxy-url> " +
        "--aas-endpoint <aas-signing-url> --aas-account-name <name> --aas-cert-profile-name <name> " +
        "--payload <file> --sf <statement-output-file> [--output <result-file>] " +
        "[--ha <SHA256|SHA384|SHA512>] [--rsp <PSS|PKCS1>] [--cbph <label=base64-cbor>] " +
        "[--timeout <seconds>] [--correlation-id <id>] [--aas-exclude-credentials <names>]";

    /// <inheritdoc/>
    public string CertificateProviderName => "azure-artifact-signing";

    /// <inheritdoc/>
    public bool EmbedPayload => true;

    /// <inheritdoc/>
    public override IDictionary<string, string> Options { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["endpoint"] = "Microsoft Signing Transparency ledger endpoint URL (required)",
            ["proxy-endpoint"] = "Azure Artifact Signing MST proxy endpoint URL (required)",
            ["output"] = "Optional path for the JSON registration result",
            ["timeout"] = "MST registration timeout in seconds (default: 30)",
            ["correlation-id"] = "Optional correlation ID sent to Azure Artifact Signing",
        };

    /// <inheritdoc/>
    public override async Task<PluginExitCode> ExecuteAsync(
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        try
        {
            string ledgerEndpoint = GetRequiredNonWhitespaceValue(configuration, "endpoint");
            string proxyEndpoint = GetRequiredNonWhitespaceValue(configuration, "proxy-endpoint");
            string accountName = GetRequiredNonWhitespaceValue(configuration, "aas-account-name");
            string certificateProfileName = GetRequiredNonWhitespaceValue(configuration, "aas-cert-profile-name");
            string payloadPath = GetRequiredNonWhitespaceValue(configuration, "PayloadFile");
            string signaturePath = GetRequiredNonWhitespaceValue(configuration, "SignatureFile");
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

            if (!File.Exists(signaturePath))
            {
                Logger.LogError($"Generated COSE statement not found: {signaturePath}");
                return PluginExitCode.UserSpecifiedFileNotFound;
            }

            IReadOnlyList<string> excludedCredentials = AzureCredentialFactory.GetExclusions(configuration);
            _ = AzureCredentialFactory.GetCredential(excludedCredentials, Logger);

            using CancellationTokenSource timeoutCts = new(TimeSpan.FromSeconds(timeoutSeconds));
            using CancellationTokenSource linkedCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            byte[] statementBytes = await File.ReadAllBytesAsync(signaturePath, linkedCts.Token).ConfigureAwait(false);

            Logger.LogInformation("Registering the generated COSE statement with MST through Azure Artifact Signing...");
            Logger.LogVerbose($"  Ledger endpoint: {ledgerEndpointUri}");
            Logger.LogVerbose($"  Proxy endpoint: {proxyEndpointUri}");
            Logger.LogVerbose($"  Signature: {signaturePath} ({statementBytes.Length} bytes)");

            TransparencyClient client = this.transparencyClientFactory(proxyEndpointUri!, configuration, Logger);
            string mstInstanceName = ledgerEndpointUri!.Host.Split('.')[0];

            using MemoryStream statementStream = new(statementBytes, writable: false);
            Response<Stream> response = await client.RegisterTransparencyAsync(
                accountName,
                certificateProfileName,
                mstInstanceName,
                statementStream,
                correlationId,
                linkedCts.Token).ConfigureAwait(false);

            byte[] receipt;
            await using (Stream receiptStream = response.Value)
            {
                using MemoryStream receiptBuffer = new();
                await receiptStream.CopyToAsync(receiptBuffer, linkedCts.Token).ConfigureAwait(false);
                receipt = receiptBuffer.ToArray();
            }

            Logger.LogInformation("Signing and registration through Azure Artifact Signing completed successfully.");

            if (!string.IsNullOrWhiteSpace(outputPath))
            {
                var result = new
                {
                    AccountName = accountName,
                    CertificateProfileName = certificateProfileName,
                    MstInstanceName = mstInstanceName,
                    PayloadPath = payloadPath,
                    SignaturePath = signaturePath,
                    RegistrationTime = DateTime.UtcNow,
                    TransparencyReceipt = Convert.ToBase64String(receipt),
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
            Logger.LogError($"Azure Artifact Signing operation failed: HTTP {ex.Status}, {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (AuthenticationFailedException ex)
        {
            Logger.LogError($"Failed to authenticate to Azure Artifact Signing: {ex.Message}");
            Logger.LogException(ex);
            return PluginExitCode.UnknownError;
        }
        catch (InvalidOperationException ex)
        {
            Logger.LogError($"Azure Artifact Signing failed: {ex.Message}");
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
