// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Transparent.MST.Extensions;
using System.Security.Cryptography.Cose;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Command to register a COSE Sign1 message with Microsoft's Signing Transparency (MST).
/// </summary>
public class RegisterCommand : MstCommandBase
{
    /// <inheritdoc/>
    public override string Name => "mst_register";

    /// <inheritdoc/>
    public override string Description => "Register a COSE Sign1 message with Microsoft's Signing Transparency (MST)";

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage(Name, "register") + 
        $"  --timeout       Timeout in seconds (default: 30){Environment.NewLine}" +
        $"{Environment.NewLine}" +
        $"Examples:{Environment.NewLine}" +
        GetExamples();

    /// <inheritdoc/>
    protected override string GetExamples()
    {
        return $"  CoseSignTool mst_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose{Environment.NewLine}" +
               $"  CoseSignTool mst_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --output result.json{Environment.NewLine}" +
               $"  CoseSignTool mst_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --token-env MY_TOKEN_VAR";
    }

    /// <inheritdoc/>
    public override IDictionary<string, string> Options => CommonOptions;

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
        Logger.LogVerbose("Creating transparency service");
        // Create the transparency service with logging
        CoseSign1.Transparent.Interfaces.ITransparencyService transparencyService = client.ToCoseSign1TransparencyService(
            logVerbose: Logger.LogVerbose,
            logWarning: Logger.LogWarning,
            logError: Logger.LogError);

        PrintOperationStatus("Registering", endpoint, payloadPath, signaturePath, signatureBytes.Length);

        Logger.LogVerbose("Calling MakeTransparentAsync...");
        // Register with the transparency service
        CoseSign1Message result = await transparencyService.MakeTransparentAsync(message, cancellationToken);

        Logger.LogInformation("Registration completed successfully.");

        // Create result object for JSON output
        var jsonResult = new
        {
            Endpoint = endpoint,
            PayloadPath = payloadPath,
            SignaturePath = signaturePath,
            RegistrationTime = DateTime.UtcNow,
            TransparentMessage = Convert.ToBase64String(result.Encode())
        };

        return (PluginExitCode.Success, jsonResult);
    }
}
