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
/// Verification provider for SCITT receipt validation backed by Microsoft Signing Transparency.
/// </summary>
public class MstVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy, IVerificationRootProvider, IVerificationRootFeaturesProvider
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string RootId = "scitt";
        public const string RootHelpSummary = "Verify using SCITT receipt trust";
        public const string ProviderName = "SCITT";
        public const string ProviderDescription = "SCITT receipt validation using Microsoft Signing Transparency";

        public const string OptionIssuer = "--issuer";
        public const string OptionIssuerOfflineKeys = "--issuer-offline-keys";

        public const string DescriptionIssuer = "Issuer(s) to trust (repeatable). Values may be absolute URLs or issuer hosts.";
        public const string DescriptionIssuerOfflineKeys = "Offline JWKS for specific issuer";

        public const string MetadataKeyScittTrust = "SCITT Trust";
        public const string MetadataKeyScittOfflineKeys = "SCITT Offline Keys";
        public const string MetadataKeyScittTrustedIssuers = "SCITT Trusted Issuers";
        public const string Yes = "Yes";
        public const string No = "No";

        public const string JsonPropertyKeys = "keys";

        public const string ReceiptMustBePresentFailure = "SCITT receipt must be present";
        public const string ReceiptMustBeVerifiedFailure = "SCITT receipt must be cryptographically verified";
        public const string ReceiptIssuerMustBeTrustedFailureFormat = "SCITT receipt issuer must be one of: {0}";

        public const string ErrorScittTrustRequiresConfiguration = "SCITT verification requires one or more --issuer <url> values or --issuer-offline-keys <issuer=path> mappings.";
        public const string ErrorIssuerOfflineKeysFormatInvalid = "Issuer offline keys entry must be in '<issuer>=<path>' format: {0}";
        public const string ErrorOfflineKeysFileMissing = "Offline keys file not found: {0}";
        public const string ErrorOfflineKeysFileInvalid = "Offline keys file is not valid JWKS JSON: {0}";

        public const string ListSeparatorCommaSpace = ", ";
        public const string KeyValueSeparator = "=";
    }

    private sealed class OfflineIssuerKeyEntry
    {
        public OfflineIssuerKeyEntry(string issuerHost, string filePath, string jwksJson)
        {
            IssuerHost = issuerHost;
            FilePath = filePath;
            JwksJson = jwksJson;
        }

        public string IssuerHost { get; }

        public string FilePath { get; }

        public string JwksJson { get; }
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 100;

    /// <inheritdoc/>
    public string RootId => ClassStrings.RootId;

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
        var issuerOption = new Option<string[]?>(
            name: ClassStrings.OptionIssuer,
            description: ClassStrings.DescriptionIssuer)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        command.AddOption(issuerOption);

        var issuerOfflineKeysOption = new Option<string[]?>(
            name: ClassStrings.OptionIssuerOfflineKeys,
            description: ClassStrings.DescriptionIssuerOfflineKeys)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        command.AddOption(issuerOfflineKeysOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        ThrowIfNull(parseResult);
        return IsVerifyRoot(parseResult);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">Thrown when issuer trust configuration is missing or invalid.</exception>
    public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(validationBuilder);
        ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(context);

        if (!IsVerifyRoot(parseResult))
        {
            return;
        }

        var trustedIssuerHosts = GetTrustedIssuerHosts(parseResult);
        var offlineIssuerKeys = GetOfflineIssuerKeys(parseResult);
        var allTrustedIssuerHosts = GetAllTrustedIssuerHosts(trustedIssuerHosts, offlineIssuerKeys);

        if (allTrustedIssuerHosts.Count == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorScittTrustRequiresConfiguration);
        }

        validationBuilder.EnableMstSupport(trust =>
        {
            trust.VerifyReceipts();
            trust.Options.AuthorizedDomains = allTrustedIssuerHosts;

            if (offlineIssuerKeys.Count > 0)
            {
                trust.Options.OfflineOnly = true;
                trust.Options.HasOfflineKeys = true;
                trust.Options.OfflineTrustedJwksByIssuer = offlineIssuerKeys.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.JwksJson,
                    StringComparer.OrdinalIgnoreCase);
            }
        });
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">Thrown when issuer trust configuration is missing or invalid.</exception>
    public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
    {
        ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(context);

        if (!IsVerifyRoot(parseResult))
        {
            return null;
        }

        var trustedIssuerHosts = GetTrustedIssuerHosts(parseResult);
        var offlineIssuerKeys = GetOfflineIssuerKeys(parseResult);
        var allTrustedIssuerHosts = GetAllTrustedIssuerHosts(trustedIssuerHosts, offlineIssuerKeys);

        if (allTrustedIssuerHosts.Count == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorScittTrustRequiresConfiguration);
        }

        return TrustPlanPolicy.AnyCounterSignature(cs =>
        {
            cs.RequireFact<MstReceiptPresentFact>(
                f => f.IsPresent,
                ClassStrings.ReceiptMustBePresentFailure);

            cs.RequireFact<MstReceiptTrustedFact>(
                f => f.IsTrusted,
                ClassStrings.ReceiptMustBeVerifiedFailure);

            var hostList = string.Join(ClassStrings.ListSeparatorCommaSpace, allTrustedIssuerHosts);
            cs.RequireFact<MstReceiptIssuerHostFact>(
                f => f.Hosts.Any(h => allTrustedIssuerHosts.Any(allowed => string.Equals(h, allowed, StringComparison.OrdinalIgnoreCase))),
                string.Format(ClassStrings.ReceiptIssuerMustBeTrustedFailureFormat, hostList));

            return cs;
        });
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
            [ClassStrings.MetadataKeyScittTrust] = enabled ? ClassStrings.Yes : ClassStrings.No
        };

        if (!enabled)
        {
            return metadata;
        }

        var trustedIssuerHosts = GetTrustedIssuerHosts(parseResult);
        var offlineIssuerKeys = GetOfflineIssuerKeys(parseResult);
        var allTrustedIssuerHosts = GetAllTrustedIssuerHosts(trustedIssuerHosts, offlineIssuerKeys);
        if (allTrustedIssuerHosts.Count > 0)
        {
            metadata[ClassStrings.MetadataKeyScittTrustedIssuers] = string.Join(ClassStrings.ListSeparatorCommaSpace, allTrustedIssuerHosts);
        }

        if (offlineIssuerKeys.Count > 0)
        {
            metadata[ClassStrings.MetadataKeyScittOfflineKeys] = string.Join(
                ClassStrings.ListSeparatorCommaSpace,
                offlineIssuerKeys.Values.Select(entry => string.Concat(entry.IssuerHost, ClassStrings.KeyValueSeparator, entry.FilePath)));
        }

        return metadata;
    }

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

    private static void ThrowIfNull(ParseResult parseResult)
    {
        if (parseResult == null)
        {
            throw new ArgumentNullException(nameof(parseResult));
        }
    }

    private static List<string> GetTrustedIssuerHosts(ParseResult parseResult)
    {
        var issuerOption = FindOption<string[]?>(parseResult, ClassStrings.OptionIssuer);
        var issuers = issuerOption is not null ? parseResult.GetValueForOption(issuerOption) : null;
        return NormalizeIssuerHosts(issuers);
    }

    private static Dictionary<string, OfflineIssuerKeyEntry> GetOfflineIssuerKeys(ParseResult parseResult)
    {
        var issuerOfflineKeysOption = FindOption<string[]?>(parseResult, ClassStrings.OptionIssuerOfflineKeys);
        var issuerOfflineKeys = issuerOfflineKeysOption is not null ? parseResult.GetValueForOption(issuerOfflineKeysOption) : null;
        return ParseOfflineIssuerKeys(issuerOfflineKeys);
    }

    private static List<string> GetAllTrustedIssuerHosts(
        IReadOnlyList<string> trustedIssuerHosts,
        IReadOnlyDictionary<string, OfflineIssuerKeyEntry> offlineIssuerKeys)
    {
        return trustedIssuerHosts
            .Concat(offlineIssuerKeys.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static Dictionary<string, OfflineIssuerKeyEntry> ParseOfflineIssuerKeys(string[]? mappings)
    {
        var results = new Dictionary<string, OfflineIssuerKeyEntry>(StringComparer.OrdinalIgnoreCase);

        if (mappings == null || mappings.Length == 0)
        {
            return results;
        }

        foreach (var mapping in mappings)
        {
            if (string.IsNullOrWhiteSpace(mapping))
            {
                continue;
            }

            var separatorIndex = mapping.IndexOf('=');
            if (separatorIndex <= 0 || separatorIndex == mapping.Length - 1)
            {
                throw new ArgumentException(string.Format(ClassStrings.ErrorIssuerOfflineKeysFormatInvalid, mapping));
            }

            var issuerToken = mapping[..separatorIndex].Trim();
            var pathToken = mapping[(separatorIndex + 1)..].Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(pathToken))
            {
                throw new ArgumentException(string.Format(ClassStrings.ErrorIssuerOfflineKeysFormatInvalid, mapping));
            }

            var normalizedIssuerHosts = NormalizeIssuerHosts([issuerToken]);
            if (normalizedIssuerHosts.Count == 0)
            {
                throw new ArgumentException(string.Format(ClassStrings.ErrorIssuerOfflineKeysFormatInvalid, mapping));
            }

            var file = new FileInfo(pathToken);
            if (!file.Exists)
            {
                throw new ArgumentException(string.Format(ClassStrings.ErrorOfflineKeysFileMissing, file.FullName));
            }

            if (!TryReadJwksJson(file, out var jwksJson) || string.IsNullOrWhiteSpace(jwksJson))
            {
                throw new ArgumentException(string.Format(ClassStrings.ErrorOfflineKeysFileInvalid, file.FullName));
            }

            var issuerHost = normalizedIssuerHosts[0];
            results[issuerHost] = new OfflineIssuerKeyEntry(issuerHost, file.FullName, jwksJson);
        }

        return results;
    }

    private static List<string> NormalizeIssuerHosts(string[]? issuers)
    {
        var results = new List<string>();

        if (issuers == null || issuers.Length == 0)
        {
            return results;
        }

        foreach (var issuer in issuers)
        {
            var normalizedHost = NormalizeIssuerHost(issuer);
            if (!string.IsNullOrWhiteSpace(normalizedHost) && !results.Contains(normalizedHost, StringComparer.OrdinalIgnoreCase))
            {
                results.Add(normalizedHost);
            }
        }

        return results;
    }

    private static string? NormalizeIssuerHost(string? issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            return null;
        }

        var trimmed = issuer.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            return string.IsNullOrWhiteSpace(uri.Host) ? null : uri.Host;
        }

        return trimmed;
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
}
