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
/// Provides trust assertion based on Key Vault kid URI patterns.
/// </summary>
/// <remarks>
/// This provider validates that the kid header matches allowed Azure Key Vault patterns.
/// Actual signature verification requires a signing key resolver capable of extracting
/// or fetching the public key from the COSE_Key header or Key Vault service.
/// </remarks>
public sealed class AzureKeyVaultVerificationProvider : IVerificationProviderWithContext
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "AzureKeyVault";
        public const string ProviderDescription = "Azure Key Vault key-only signature verification (kid pattern validation)";

        public const string OptionRequireAzKey = "--require-az-key";
        public const string OptionAllowedVaults = "--allowed-vaults";

        public const string DescriptionRequireAzKey =
            "Require an Azure Key Vault key signature (kid must be an AKV URI)";
        public const string DescriptionAllowedVaults =
            "Allowed Key Vault URI patterns (glob or regex: prefix). Repeat for multiple.";

        public const string MetadataKeyAkvValidation = "AKV Validation";
        public const string MetadataKeyRequireAkvKey = "Require AKV Key";
        public const string MetadataKeyAllowedVaults = "Allowed Vault Patterns";

        public const string MetadataValueEnabled = "Enabled";
        public const string Yes = "Yes";
        public const string No = "No";
        public const string None = "None";
        public const string ListSeparator = ", ";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 20; // Trust/assertion validation

    private Option<bool> RequireAzKeyOption = null!;
    private Option<string[]> AllowedVaultsOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        RequireAzKeyOption = new Option<bool>(
            name: ClassStrings.OptionRequireAzKey,
            description: ClassStrings.DescriptionRequireAzKey);
        command.AddOption(RequireAzKeyOption);

        AllowedVaultsOption = new Option<string[]>(
            name: ClassStrings.OptionAllowedVaults,
            description: ClassStrings.DescriptionAllowedVaults)
        {
            Arity = ArgumentArity.ZeroOrMore,
            AllowMultipleArgumentsPerToken = true
        };
        command.AddOption(AllowedVaultsOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        // Activate if any AKV-specific options are provided
        bool requireAzKey = RequireAzKeyOption != null && parseResult.GetValueForOption(RequireAzKeyOption);
        var allowedVaults = AllowedVaultsOption != null ? parseResult.GetValueForOption(AllowedVaultsOption) : null;
        
        return requireAzKey || (allowedVaults != null && allowedVaults.Length > 0);
    }

    /// <inheritdoc/>
    public IEnumerable<IValidationComponent> CreateValidators(ParseResult parseResult)
    {
        return CreateValidatorsCore(parseResult);
    }

    /// <inheritdoc/>
    public IEnumerable<IValidationComponent> CreateValidators(ParseResult parseResult, VerificationContext context)
    {
        return CreateValidatorsCore(parseResult);
    }

    private IEnumerable<IValidationComponent> CreateValidatorsCore(ParseResult parseResult)
    {
        bool requireAzKey = RequireAzKeyOption != null && parseResult.GetValueForOption(RequireAzKeyOption);
        var allowedVaults = AllowedVaultsOption != null ? parseResult.GetValueForOption(AllowedVaultsOption) : null;

        // Only add the assertion provider if there are patterns to match against
        if (allowedVaults != null && allowedVaults.Length > 0)
        {
            yield return new AzureKeyVaultAssertionProvider(
                allowedPatterns: allowedVaults,
                requireAzureKeyVaultKey: requireAzKey);
        }
    }

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
    {
        bool requireAzKey = RequireAzKeyOption != null && parseResult.GetValueForOption(RequireAzKeyOption);
        var allowedVaults = AllowedVaultsOption != null ? parseResult.GetValueForOption(AllowedVaultsOption) : null;

        var metadata = new Dictionary<string, object?>
        {
            [ClassStrings.MetadataKeyAkvValidation] = ClassStrings.MetadataValueEnabled,
            [ClassStrings.MetadataKeyRequireAkvKey] = requireAzKey ? ClassStrings.Yes : ClassStrings.No
        };

        if (allowedVaults != null && allowedVaults.Length > 0)
        {
            metadata[ClassStrings.MetadataKeyAllowedVaults] = string.Join(ClassStrings.ListSeparator, allowedVaults);
        }
        else
        {
            metadata[ClassStrings.MetadataKeyAllowedVaults] = ClassStrings.None;
        }

        return metadata;
    }
}
