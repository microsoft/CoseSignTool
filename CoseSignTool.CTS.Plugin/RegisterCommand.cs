// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Transparent.CTS.Extensions;
using System.Security.Cryptography.Cose;

namespace CoseSignTool.CTS.Plugin;

/// <summary>
/// Command to register a COSE Sign1 message with Azure Code Transparency Service.
/// </summary>
public class RegisterCommand : CtsCommandBase
{
    /// <inheritdoc/>
    public override string Name => "cts_register";

    /// <inheritdoc/>
    public override string Description => "Register a COSE Sign1 message with Azure Code Transparency Service";

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage(Name, "register") + 
        $"  --timeout       Timeout in seconds (default: 30){Environment.NewLine}" +
        $"{Environment.NewLine}" +
        $"Examples:{Environment.NewLine}" +
        GetExamples();

    /// <inheritdoc/>
    protected override string GetExamples()
    {
        return $"  CoseSignTool cts_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose{Environment.NewLine}" +
               $"  CoseSignTool cts_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --output result.json{Environment.NewLine}" +
               $"  CoseSignTool cts_register --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --token-env MY_TOKEN_VAR";
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
        // Create the transparency service
        var transparencyService = client.ToCoseSign1TransparencyService();

        PrintOperationStatus("Registering", endpoint, payloadPath, signaturePath, signatureBytes.Length);

        // Register with the transparency service
        var result = await transparencyService.MakeTransparentAsync(message, cancellationToken);

        Console.WriteLine("Registration completed successfully.");

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
