// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;

namespace CoseSignTool.AzureKeyVault.Plugin;

/// <summary>
/// Verification provider for Azure Key Vault key-only signatures.
/// Uses an embedded COSE_Key public key for offline verification.
/// </summary>
public sealed class AzureKeyVaultVerificationProvider : IVerificationProviderWithContext
{
    public string ProviderName => "AzureKeyVault";

    public string Description => "Azure Key Vault key-only signature verification (kid + embedded COSE_Key)";

    public int Priority => 0; // Signature validation

    private Option<bool> AllowOnlineVerifyOption = null!;
    private Option<bool> RequireAzKeyOption = null!;

    public void AddVerificationOptions(Command command)
    {
        AllowOnlineVerifyOption = new Option<bool>(
            name: "--allow-online-verify",
            description: "Allow network calls to Azure Key Vault to fetch the public key by kid when needed for verification");
        command.AddOption(AllowOnlineVerifyOption);

        RequireAzKeyOption = new Option<bool>(
            name: "--require-az-key",
            description: "Require an Azure Key Vault key-only signature (kid + COSE_Key) to be present");
        command.AddOption(RequireAzKeyOption);
    }

    public bool IsActivated(ParseResult parseResult)
    {
        // Always enabled when the plugin is loaded; the validator itself is conditional.
        return true;
    }

    public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
    {
        // Context-free path can't correctly verify detached signatures.
        // The verify command uses the context-aware overload.
        return Array.Empty<IValidator<CoseSign1Message>>();
    }

    public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult, VerificationContext context)
    {
        bool allowOnlineVerify = AllowOnlineVerifyOption != null && parseResult.GetValueForOption(AllowOnlineVerifyOption);
        bool requireAzKey = RequireAzKeyOption != null && parseResult.GetValueForOption(RequireAzKeyOption);

        return new[]
        {
            new AzureKeyVaultSignatureValidator(
                context.DetachedPayload,
                requireAzureKey: requireAzKey,
                allowOnlineVerify: allowOnlineVerify)
        };
    }

    public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
    {
        bool allowOnlineVerify = AllowOnlineVerifyOption != null && parseResult.GetValueForOption(AllowOnlineVerifyOption);
        bool requireAzKey = RequireAzKeyOption != null && parseResult.GetValueForOption(RequireAzKeyOption);

        return new Dictionary<string, object?>
        {
            ["AKV Key-Only Verification"] = "Enabled",
            ["Allow Online Verify"] = allowOnlineVerify ? "Yes" : "No",
            ["Require AKV Key"] = requireAzKey ? "Yes" : "No"
        };
    }
}
