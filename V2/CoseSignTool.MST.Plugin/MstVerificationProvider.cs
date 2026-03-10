// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Text.Json;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Verification provider for Microsoft Signing Transparency (MST) receipt validation.
/// Validates that signatures contain valid SCITT receipts from the MST service.
/// </summary>
public class MstVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy, IVerificationRootProvider, IVerificationRootFeaturesProvider
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string CommandVerify = "verify";

        public const string RootId = "mst";

        public const string RootHelpSummary = "Verify using MST receipt trust";

        public const string ProviderName = "MST";
        public const string ProviderDescription = "Microsoft Signing Transparency receipt validation";

        public const string OptionMstOfflineKeys = "--mst-offline-keys";
        public const string OptionMstOfflineKeysAlias = "--offline_keys";
        public const string OptionMstTrustLedgerInstance = "--mst-trust-ledger-instance";

        public const string DescriptionMstOfflineKeys = "Pinned MST signing keys JWKS JSON file used for offline-only receipt verification";
        public const string DescriptionMstTrustLedgerInstance = "Allowed MST ledger instance (issuer host). Repeatable. Values may be hostnames or URLs.";

        public const string MetadataKeyMstTrust = "MST Trust";
        public const string MetadataKeyMstOfflineKeys = "MST Offline Keys";
        public const string MetadataKeyMstTrustedLedgers = "MST Trusted Ledgers";
        public const string Yes = "Yes";
        public const string No = "No";

        public const string JsonPropertyKeys = "keys";

        public const string ReceiptMustBePresentFailure = "MST receipt must be present";
        public const string ReceiptMustBeVerifiedFailure = "MST receipt must be cryptographically verified";
        public const string ReceiptIssuerMustBeTrustedFailureFormat = "MST receipt issuer must be one of: {0}";

        public const string ErrorMstTrustRequiresConfiguration = "MST verification requires either --mst-offline-keys <path> (or --offline_keys) or one or more --mst-trust-ledger-instance <host> values.";
        public const string ErrorOfflineKeysFileMissing = "Offline keys file not found: {0}";
        public const string ErrorOfflineKeysFileInvalid = "Offline keys file is not valid JWKS JSON: {0}";

        public const string ListSeparatorCommaSpace = ", ";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 100; // After signature and chain validation

    /// <inheritdoc/>
    public string RootId => ClassStrings.RootId;

    private static bool IsVerifyRoot(ParseResult parseResult)
    {
        var commandName = parseResult?.CommandResult?.Command?.Name;
        return string.Equals(commandName, ClassStrings.RootId, StringComparison.OrdinalIgnoreCase);
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
    public string RootDisplayName => ProviderName;

    /// <inheritdoc/>
    public string RootHelpSummary => ClassStrings.RootHelpSummary;

    /// <inheritdoc/>
    public VerificationRootFeatures RootFeatures =>
        VerificationRootFeatures.PreferCounterSignatureTrust |
        VerificationRootFeatures.AllowToBeSignedAttestationToSkipPrimarySignature;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        var offlineKeysOption = new Option<FileInfo?>(
            name: ClassStrings.OptionMstOfflineKeys,
            description: ClassStrings.DescriptionMstOfflineKeys);
        offlineKeysOption.AddAlias(ClassStrings.OptionMstOfflineKeysAlias);
        command.AddOption(offlineKeysOption);

        var trustedLedgerInstancesOption = new Option<string[]?>(
            name: ClassStrings.OptionMstTrustLedgerInstance,
            description: ClassStrings.DescriptionMstTrustLedgerInstance)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        command.AddOption(trustedLedgerInstancesOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        ThrowIfNull(parseResult);
        return IsVerifyRoot(parseResult);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">
    /// Thrown when <c>--mst-trust</c> is enabled but neither <c>--mst-offline-keys</c> nor
    /// <c>--mst-trust-ledger-instance</c> is provided; or when the offline keys file is missing or invalid.
    /// </exception>
    public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(validationBuilder);
        ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(context);

        if (!IsVerifyRoot(parseResult))
        {
            // This provider only applies under `verify mst`.
            return;
        }

        var offlineKeysOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionMstOfflineKeys);
        var trustedLedgerOption = FindOption<string[]?>(parseResult, ClassStrings.OptionMstTrustLedgerInstance);

        var offlineKeysFile = offlineKeysOption != null ? parseResult.GetValueForOption(offlineKeysOption) : null;
        var trustedLedgerInstances = trustedLedgerOption != null ? parseResult.GetValueForOption(trustedLedgerOption) : null;

        var normalizedTrustedHosts = NormalizeLedgerHosts(trustedLedgerInstances);
        var hasOfflineKeys = HasValidOfflineKeysFile(offlineKeysFile);

        if (!hasOfflineKeys && normalizedTrustedHosts.Count == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorMstTrustRequiresConfiguration);
        }

        if (offlineKeysFile != null && !offlineKeysFile.Exists)
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorOfflineKeysFileMissing, offlineKeysFile.FullName));
        }

        if (offlineKeysFile != null && offlineKeysFile.Exists && !TryReadJwksJson(offlineKeysFile, out _))
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorOfflineKeysFileInvalid, offlineKeysFile.FullName));
        }

        validationBuilder.EnableMstSupport(trust =>
        {
            // MST trust implies receipt verification (online by default; offline when pinned keys are provided).
            trust.VerifyReceipts();

            if (normalizedTrustedHosts.Count > 0)
            {
                trust.Options.AuthorizedDomains = normalizedTrustedHosts;
            }

            if (hasOfflineKeys && offlineKeysFile != null && offlineKeysFile.Exists)
            {
                var jwksJson = File.ReadAllText(offlineKeysFile.FullName);
                trust.UseOfflineTrustedJwksJson(jwksJson);
            }
        });
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">
    /// Thrown when <c>--mst-trust</c> is enabled but neither <c>--mst-offline-keys</c> nor
    /// <c>--mst-trust-ledger-instance</c> is provided.
    /// </exception>
    public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
    {
        ThrowIfNull(parseResult);

        if (!IsVerifyRoot(parseResult))
        {
            return null;
        }

        var offlineKeysOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionMstOfflineKeys);
        var trustedLedgerOption = FindOption<string[]?>(parseResult, ClassStrings.OptionMstTrustLedgerInstance);

        var offlineKeysFile = offlineKeysOption != null ? parseResult.GetValueForOption(offlineKeysOption) : null;
        var trustedLedgerInstances = trustedLedgerOption != null ? parseResult.GetValueForOption(trustedLedgerOption) : null;
        var normalizedTrustedHosts = NormalizeLedgerHosts(trustedLedgerInstances);

        var hasOfflineKeys = HasValidOfflineKeysFile(offlineKeysFile);

        // Enforce that MST trust is not an implicit "any Azure ledger" trust mode.
        // If the user isn't pinning keys offline, require an explicit ledger allow-list.
        if (!hasOfflineKeys && normalizedTrustedHosts.Count == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorMstTrustRequiresConfiguration);
        }

        return TrustPlanPolicy.AnyCounterSignature(cs =>
        {
            cs.RequireFact<MstReceiptPresentFact>(
                f => f.IsPresent,
                ClassStrings.ReceiptMustBePresentFailure);

            cs.RequireFact<MstReceiptTrustedFact>(
                f => f.IsTrusted,
                ClassStrings.ReceiptMustBeVerifiedFailure);

            if (normalizedTrustedHosts.Count > 0)
            {
                var hostList = string.Join(ClassStrings.ListSeparatorCommaSpace, normalizedTrustedHosts);
                cs.RequireFact<MstReceiptIssuerHostFact>(
                    f => f.Hosts.Any(h => normalizedTrustedHosts.Any(allowed => string.Equals(h, allowed, StringComparison.OrdinalIgnoreCase))),
                    string.Format(ClassStrings.ReceiptIssuerMustBeTrustedFailureFormat, hostList));
            }

            return cs;
        });
    }

    private static void ThrowIfNull(ParseResult parseResult)
    {
        if (parseResult == null)
        {
            throw new ArgumentNullException(nameof(parseResult));
        }
    }

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        System.Security.Cryptography.Cose.CoseSign1Message message,
        CoseSign1.Validation.Results.ValidationResult validationResult)
    {
        _ = message;
        _ = validationResult;

        var enabled = IsActivated(parseResult);
        var metadata = new Dictionary<string, object?>
        {
            [ClassStrings.MetadataKeyMstTrust] = enabled ? ClassStrings.Yes : ClassStrings.No
        };

        if (!enabled)
        {
            return metadata;
        }

        var offlineKeysOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionMstOfflineKeys)
            ?? FindOption<FileInfo?>(parseResult, ClassStrings.OptionMstOfflineKeysAlias);
        var offlineKeysFile = offlineKeysOption is not null ? parseResult.GetValueForOption(offlineKeysOption) : null;
        if (offlineKeysFile != null)
        {
            metadata[ClassStrings.MetadataKeyMstOfflineKeys] = offlineKeysFile.FullName;
        }

        var trustedLedgerOption = FindOption<string[]?>(parseResult, ClassStrings.OptionMstTrustLedgerInstance);
        var trustedLedgerInstances = trustedLedgerOption is not null ? parseResult.GetValueForOption(trustedLedgerOption) : null;
        var normalizedTrustedHosts = NormalizeLedgerHosts(trustedLedgerInstances);
        if (normalizedTrustedHosts.Count > 0)
        {
            metadata[ClassStrings.MetadataKeyMstTrustedLedgers] = string.Join(ClassStrings.ListSeparatorCommaSpace, normalizedTrustedHosts);
        }

        return metadata;
    }

    #region Helper Methods

    private static List<string> NormalizeLedgerHosts(string[]? instances)
    {
        var results = new List<string>();

        if (instances == null || instances.Length == 0)
        {
            return results;
        }

        foreach (var entry in instances)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            var trimmed = entry.Trim();

            // Accept hostnames or absolute URLs.
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
            {
                trimmed = uri.Host;
            }

            if (!string.IsNullOrWhiteSpace(trimmed) && !results.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
            {
                results.Add(trimmed);
            }
        }

        return results;
    }

    private static bool HasValidOfflineKeysFile(FileInfo? file)
    {
        return TryReadJwksJson(file, out _);
    }

    private static bool TryReadJwksJson(FileInfo? file, out string? jwksJson)
    {
        jwksJson = null;

        if (file == null || !file.Exists)
        {
            return false;
        }

        try
        {
            var json = File.ReadAllText(file.FullName);
            using var doc = JsonDocument.Parse(json);

            // Require a JWKS document: {"keys": [ ... ] }
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!doc.RootElement.TryGetProperty(ClassStrings.JsonPropertyKeys, out var keys) || keys.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            jwksJson = json;
            return true;
        }
        catch
        {
            return false;
        }
    }

    #endregion
}