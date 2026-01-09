// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSignTool.Abstractions;

/// <summary>
/// Verification provider for Azure Key Vault key-only signatures.
/// Uses an embedded COSE_Key public key for offline verification.
/// </summary>
public sealed class AzureKeyVaultVerificationProvider : IVerificationProviderWithContext
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "AzureKeyVault";
        public const string ProviderDescription = "Azure Key Vault key-only signature verification (kid + embedded COSE_Key)";

        public const string OptionAllowOnlineVerify = "--allow-online-verify";
        public const string OptionRequireAzKey = "--require-az-key";

        public const string DescriptionAllowOnlineVerify =
            "Allow network calls to Azure Key Vault to fetch the public key by kid when needed for verification";
        public const string DescriptionRequireAzKey =
            "Require an Azure Key Vault key-only signature (kid + COSE_Key) to be present";

        public const string MetadataKeyAkvKeyOnlyVerification = "AKV Key-Only Verification";
        public const string MetadataKeyAllowOnlineVerify = "Allow Online Verify";
        public const string MetadataKeyRequireAkvKey = "Require AKV Key";

        public const string MetadataValueEnabled = "Enabled";
        public const string Yes = "Yes";
        public const string No = "No";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 0; // Signature validation

    private Option<bool> AllowOnlineVerifyOption = null!;
    private Option<bool> RequireAzKeyOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        AllowOnlineVerifyOption = new Option<bool>(
            name: ClassStrings.OptionAllowOnlineVerify,
            description: ClassStrings.DescriptionAllowOnlineVerify);
        command.AddOption(AllowOnlineVerifyOption);

        RequireAzKeyOption = new Option<bool>(
            name: ClassStrings.OptionRequireAzKey,
            description: ClassStrings.DescriptionRequireAzKey);
        command.AddOption(RequireAzKeyOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        // Always enabled when the plugin is loaded; the validator itself is conditional.
        return true;
    }

    /// <inheritdoc/>
    public IEnumerable<IValidator> CreateValidators(ParseResult parseResult)
    {
        // Context-free path can't correctly verify detached signatures.
        // The verify command uses the context-aware overload.
        return Array.Empty<IValidator>();
    }

    /// <inheritdoc/>
    public IEnumerable<IValidator> CreateValidators(ParseResult parseResult, VerificationContext context)
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

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
    {
        bool allowOnlineVerify = AllowOnlineVerifyOption != null && parseResult.GetValueForOption(AllowOnlineVerifyOption);
        bool requireAzKey = RequireAzKeyOption != null && parseResult.GetValueForOption(RequireAzKeyOption);

        return new Dictionary<string, object?>
        {
            [ClassStrings.MetadataKeyAkvKeyOnlyVerification] = ClassStrings.MetadataValueEnabled,
            [ClassStrings.MetadataKeyAllowOnlineVerify] = allowOnlineVerify ? ClassStrings.Yes : ClassStrings.No,
            [ClassStrings.MetadataKeyRequireAkvKey] = requireAzKey ? ClassStrings.Yes : ClassStrings.No
        };
    }
}
