// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.CTS.Plugin;

using Azure.Security.CodeTransparency;
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
            { "receipt", "The file path to a specific receipt to use for verification (optional)" },
            { "authorized-domains", "Comma-separated list of authorized issuer domains for receipt verification (optional)" },
            { "authorized-receipt-behavior", "Behavior for authorized receipts: VerifyAnyMatching, VerifyAllMatching, or RequireAll (default: VerifyAllMatching)" },
            { "unauthorized-receipt-behavior", "Behavior for unauthorized receipts: VerifyAll, IgnoreAll, or FailIfPresent (default: FailIfPresent)" }
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
               $"  CoseSignTool cts_verify --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --token-env MY_TOKEN_VAR{Environment.NewLine}" +
               $"  CoseSignTool cts_verify --endpoint https://example.confidential-ledger.azure.com --payload payload.bin --signature signature.cose --authorized-domains example.com,trusted.azure.com --authorized-receipt-behavior RequireAll";
    }

    /// <inheritdoc/>
    protected override string GetAdditionalOptionalArguments()
    {
        return $"  --receipt                          File path to a specific receipt to use for verification{Environment.NewLine}" +
               $"  --authorized-domains               Comma-separated list of authorized issuer domains{Environment.NewLine}" +
               $"  --authorized-receipt-behavior      Behavior for authorized receipts (VerifyAnyMatching, VerifyAllMatching, RequireAll){Environment.NewLine}" +
               $"  --unauthorized-receipt-behavior    Behavior for unauthorized receipts (VerifyAll, IgnoreAll, FailIfPresent){Environment.NewLine}";
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

        // Parse verification options from command-line arguments
        CodeTransparencyVerificationOptions? verificationOptions = ParseVerificationOptions(configuration);
        
        Logger.LogVerbose("Creating transparency service with verification options");
        
        // Create the transparency service with verification options and logging
        CoseSign1.Transparent.Interfaces.ITransparencyService transparencyService = 
            new CoseSign1.Transparent.CTS.AzureCtsTransparencyService(
                client, 
                verificationOptions, 
                null,
                msg => Logger.LogVerbose(msg),
                msg => Logger.LogWarning(msg),
                msg => Logger.LogError(msg));

        string additionalInfo = !string.IsNullOrEmpty(receiptPath) ? $"Receipt: {receiptPath}" : null;
        PrintOperationStatus("Verifying", endpoint, payloadPath, signaturePath, signatureBytes.Length, additionalInfo);

        // Verify with the transparency service
        bool isValid;
        if (!string.IsNullOrEmpty(receiptPath))
        {
            Logger.LogVerbose($"Verifying with specific receipt from: {receiptPath}");
            // Verify with a specific receipt
            byte[] receipt = await File.ReadAllBytesAsync(receiptPath, cancellationToken);
            Logger.LogVerbose($"Receipt size: {receipt.Length} bytes");
            isValid = await transparencyService.VerifyTransparencyAsync(message, receipt, cancellationToken);
        }
        else
        {
            Logger.LogVerbose("Verifying using embedded transparency information");
            // Verify using embedded transparency information
            isValid = await message.VerifyTransparencyAsync(transparencyService, cancellationToken);
        }

        if (isValid)
        {
            Logger.LogInformation("Verification result: VALID");
        }
        else
        {
            Logger.LogError("Verification result: INVALID");
        }

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
        PluginExitCode exitCode = isValid ? PluginExitCode.Success : PluginExitCode.InvalidArgumentValue;
        return (exitCode, jsonResult);
    }

    /// <summary>
    /// Parses verification options from configuration.
    /// </summary>
    /// <param name="configuration">The configuration containing command-line arguments.</param>
    /// <returns>Verification options if any are specified, otherwise null.</returns>
    private CodeTransparencyVerificationOptions? ParseVerificationOptions(IConfiguration configuration)
    {
        string? authorizedDomainsStr = GetOptionalValue(configuration, "authorized-domains");
        string? authorizedBehaviorStr = GetOptionalValue(configuration, "authorized-receipt-behavior");
        string? unauthorizedBehaviorStr = GetOptionalValue(configuration, "unauthorized-receipt-behavior");

        // If no options are specified, return null to use defaults
        if (string.IsNullOrEmpty(authorizedDomainsStr) && 
            string.IsNullOrEmpty(authorizedBehaviorStr) && 
            string.IsNullOrEmpty(unauthorizedBehaviorStr))
        {
            return null;
        }

        var options = new CodeTransparencyVerificationOptions();

        // Parse authorized domains
        if (!string.IsNullOrEmpty(authorizedDomainsStr))
        {
            var domains = authorizedDomainsStr.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(d => d.Trim())
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .ToList();
            
            foreach (var domain in domains)
            {
                options.AuthorizedDomains.Add(domain);
            }
        }

        // Parse authorized receipt behavior
        if (!string.IsNullOrEmpty(authorizedBehaviorStr))
        {
            if (Enum.TryParse<AuthorizedReceiptBehavior>(authorizedBehaviorStr, true, out var authorizedBehavior))
            {
                options.AuthorizedReceiptBehavior = authorizedBehavior;
            }
            else
            {
                Logger?.LogWarning($"Invalid authorized-receipt-behavior value '{authorizedBehaviorStr}'. Using default.");
            }
        }

        // Parse unauthorized receipt behavior
        if (!string.IsNullOrEmpty(unauthorizedBehaviorStr))
        {
            if (Enum.TryParse<UnauthorizedReceiptBehavior>(unauthorizedBehaviorStr, true, out var unauthorizedBehavior))            {
                options.UnauthorizedReceiptBehavior = unauthorizedBehavior;
            }
            else
            {
                Logger?.LogWarning($"Invalid unauthorized-receipt-behavior value '{unauthorizedBehaviorStr}'. Using default.");
            }
        }

        return options;
    }
}
