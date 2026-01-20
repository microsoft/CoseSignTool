// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.AzureKeyVault.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Verification provider for Azure Key Vault key-only signatures.
/// Provides TrustPlan-based trust evaluation based on Key Vault kid URI patterns.
/// </summary>
/// <remarks>
/// For offline cryptographic verification, it also contributes a signing key resolver
/// that can extract an embedded COSE_Key public key header.
/// </remarks>
public sealed class AzureKeyVaultVerificationProvider : IVerificationProviderWithTrustPlanPolicy, IVerificationRootProvider
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "AzureKeyVault";
        public const string ProviderDescription = "Azure Key Vault key-only signature verification (kid pattern validation)";

        public const string VerifyRootAkv = "akv";

        public const string RootHelpSummary = "Verify Azure Key Vault key-only signatures";

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

        public const string TrustReasonKidMustBeAkv = "kid must be an Azure Key Vault key URI";
        public const string TrustReasonKidMustMatchAllowedPatterns = "kid must match one of the allowed Azure Key Vault patterns";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 20; // Trust/assertion validation

    /// <inheritdoc/>
    public string RootId => ClassStrings.VerifyRootAkv;

    /// <inheritdoc/>
    public string RootDisplayName => ProviderName;

    /// <inheritdoc/>
    public string RootHelpSummary => ClassStrings.RootHelpSummary;

    private static bool IsAkvRoot(ParseResult parseResult)
    {
        var commandName = parseResult?.CommandResult?.Command?.Name;
        return string.Equals(commandName, ClassStrings.VerifyRootAkv, StringComparison.OrdinalIgnoreCase);
    }

    private static Option<T>? FindOption<T>(ParseResult parseResult, string optionToken)
    {
        var normalized = optionToken.TrimStart('-');

        for (var current = parseResult.CommandResult; current != null; current = current.Parent as CommandResult)
        {
            foreach (var opt in current.Command.Options)
            {
                if (string.Equals(opt.Name, normalized, StringComparison.OrdinalIgnoreCase))
                {
                    return opt as Option<T>;
                }

                foreach (var alias in opt.Aliases)
                {
                    if (string.Equals(alias.TrimStart('-'), normalized, StringComparison.OrdinalIgnoreCase))
                    {
                        return opt as Option<T>;
                    }
                }
            }
        }

        return null;
    }

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        var requireAzKeyOption = new Option<bool>(
            name: ClassStrings.OptionRequireAzKey,
            description: ClassStrings.DescriptionRequireAzKey);
        command.AddOption(requireAzKeyOption);

        var allowedVaultsOption = new Option<string[]>(
            name: ClassStrings.OptionAllowedVaults,
            description: ClassStrings.DescriptionAllowedVaults)
        {
            Arity = ArgumentArity.ZeroOrMore,
            AllowMultipleArgumentsPerToken = true
        };
        command.AddOption(allowedVaultsOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        // Active under `verify akv`, or when any AKV-specific options are provided.
        if (IsAkvRoot(parseResult))
        {
            return true;
        }

        var requireAzKeyOption = FindOption<bool>(parseResult, ClassStrings.OptionRequireAzKey);
        var allowedVaultsOption = FindOption<string[]>(parseResult, ClassStrings.OptionAllowedVaults);

        bool requireAzKey = requireAzKeyOption != null && parseResult.GetValueForOption(requireAzKeyOption);
        var allowedVaults = allowedVaultsOption != null ? parseResult.GetValueForOption(allowedVaultsOption) : null;

        return requireAzKey || (allowedVaults != null && allowedVaults.Length > 0);
    }

    /// <inheritdoc/>
    public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(validationBuilder);
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(context);

        var requireAzKeyOption = FindOption<bool>(parseResult, ClassStrings.OptionRequireAzKey);
        var allowedVaultsOption = FindOption<string[]>(parseResult, ClassStrings.OptionAllowedVaults);

        bool requireAzKey = IsAkvRoot(parseResult) || (requireAzKeyOption != null && parseResult.GetValueForOption(requireAzKeyOption));
        var allowedVaults = allowedVaultsOption != null ? parseResult.GetValueForOption(allowedVaultsOption) : null;

        // CLI provider is offline by default. Online key-fetching requires additional DI configuration
        // (Key Vault client factory) and should be explicitly enabled elsewhere.
        validationBuilder.EnableAzureKeyVaultSupport(akv =>
        {
            akv.OfflineOnly();

            if (requireAzKey)
            {
                akv.RequireAzureKeyVaultKid();
            }

            if (allowedVaults != null && allowedVaults.Length > 0)
            {
                akv.AllowKidPatterns(allowedVaults);
            }
        });
    }

    /// <inheritdoc/>
    public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
    {
        var requireAzKeyOption = FindOption<bool>(parseResult, ClassStrings.OptionRequireAzKey);
        var allowedVaultsOption = FindOption<string[]>(parseResult, ClassStrings.OptionAllowedVaults);

        bool requireAzKey = IsAkvRoot(parseResult) || (requireAzKeyOption != null && parseResult.GetValueForOption(requireAzKeyOption));
        var allowedVaults = allowedVaultsOption != null ? parseResult.GetValueForOption(allowedVaultsOption) : null;

        if (allowedVaults != null && allowedVaults.Length > 0)
        {
            return TrustPlanPolicy.Message(m => m.RequireFact<AzureKeyVaultKidAllowedFact>(
                f => f.IsAllowed,
                ClassStrings.TrustReasonKidMustMatchAllowedPatterns));
        }

        if (requireAzKey)
        {
            return TrustPlanPolicy.Message(m => m.RequireFact<AzureKeyVaultKidDetectedFact>(
                f => f.IsAzureKeyVaultKey,
                ClassStrings.TrustReasonKidMustBeAkv));
        }

        return TrustPlanPolicy.Message(_ => _);
    }

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
    {
        var requireAzKeyOption = FindOption<bool>(parseResult, ClassStrings.OptionRequireAzKey);
        var allowedVaultsOption = FindOption<string[]>(parseResult, ClassStrings.OptionAllowedVaults);

        bool requireAzKey = IsAkvRoot(parseResult) || (requireAzKeyOption != null && parseResult.GetValueForOption(requireAzKeyOption));
        var allowedVaults = allowedVaultsOption != null ? parseResult.GetValueForOption(allowedVaultsOption) : null;

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
