// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.CTS.Plugin;

using CoseSign1.Transparent.Extensions;
using System.Security.Cryptography.Cose;

/// <summary>
/// Command to verify a COSE Sign1 message with Azure Code Transparency Service.
/// </summary>
public class VerifyCommand : CtsCommandBase
{
    private static readonly Dictionary<string, string> VerifyOptions = 
        CommonOptions.Concat(new Dictionary<string, string>
        {
            { "receipt", "The file path to a specific receipt to use for verification (optional)" }
        }).ToDictionary(k => k.Key, k => k.Value);

    /// <inheritdoc/>
    public override string Name => "cts_verify";

    /// <inheritdoc/>
    public override string Description => "Verify a COSE Sign1 message with Azure Code Transparency Service";

    /// <inheritdoc/>
    public override string Usage => GetBaseUsage(Name, "verify") + 
        GetAdditionalOptionalArguments() +
        $"  --timeout       Timeout in seconds (default: 30){Environment.NewLine}" +
        $"{Environment.NewLine}" +
        $"Examples:{Environment.NewLine}" +
        GetExamples();

    /// <inheritdoc/>
    protected override string GetExamples()
    {
        return $"  CoseSignTool cts_verify --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose{Environment.NewLine}" +
               $"  CoseSignTool cts_verify --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --receipt receipt.cose --output verification.json{Environment.NewLine}" +
               $"  CoseSignTool cts_verify --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --token-env MY_TOKEN_VAR";
    }

    /// <inheritdoc/>
    protected override string GetAdditionalOptionalArguments()
    {
        return $"  --receipt       File path to a specific receipt to use for verification{Environment.NewLine}";
    }

    /// <inheritdoc/>
    public override IDictionary<string, string> Options => VerifyOptions;

    /// <inheritdoc/>
    protected override void AddAdditionalFileValidation(Dictionary<string, string> requiredFiles, IConfiguration configuration)
    {
        string? receiptPath = GetOptionalValue(configuration, "receipt");
        if (!string.IsNullOrEmpty(receiptPath))
        {
            requiredFiles.Add("Receipt", receiptPath);
        }
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
        string? receiptPath = GetOptionalValue(configuration, "receipt");
        
        // Create the transparency service
        var transparencyService = client.ToCoseSign1TransparencyService();

        string additionalInfo = !string.IsNullOrEmpty(receiptPath) ? $"Receipt: {receiptPath}" : null;
        PrintOperationStatus("Verifying", endpoint, payloadPath, signaturePath, signatureBytes.Length, additionalInfo);

        // Verify with the transparency service
        bool isValid;
        if (!string.IsNullOrEmpty(receiptPath))
        {
            // Verify with a specific receipt
            byte[] receipt = await File.ReadAllBytesAsync(receiptPath, cancellationToken);
            isValid = await transparencyService.VerifyTransparencyAsync(message, receipt, cancellationToken);
        }
        else
        {
            // Verify using embedded transparency information
            isValid = await message.VerifyTransparencyAsync(transparencyService, cancellationToken);
        }

        Console.WriteLine($"Verification result: {(isValid ? "VALID" : "INVALID")}");

        // Create result object for JSON output
        var jsonResult = new
        {
            Endpoint = endpoint,
            PayloadPath = payloadPath,
            SignaturePath = signaturePath,
            ReceiptPath = receiptPath,
            VerificationTime = DateTime.UtcNow,
            IsValid = isValid
        };

        // Return appropriate exit code based on verification result
        var exitCode = isValid ? PluginExitCode.Success : PluginExitCode.InvalidArgumentValue;
        return (exitCode, jsonResult);
    }
}
