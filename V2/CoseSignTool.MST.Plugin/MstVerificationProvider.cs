// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.ClientModel.Primitives;
using System.Security.Cryptography.Cose;
using System.Text;
using System.Text.Json;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSignTool.Abstractions;

/// <summary>
/// Verification provider for Microsoft Signing Transparency (MST) receipt validation.
/// Validates that signatures contain valid SCITT receipts from the MST service.
/// </summary>
public class MstVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPolicy
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "MST";
        public const string ProviderDescription = "Microsoft Signing Transparency receipt validation";

        public const string OptionRequireReceipt = "--require-receipt";
        public const string OptionMstEndpoint = "--mst-endpoint";
        public const string OptionVerifyReceipt = "--verify-receipt";
        public const string OptionMstTrustMode = "--mst-trust-mode";
        public const string OptionMstTrustFile = "--mst-trust-file";
        public const string OptionMstTrustedKey = "--mst-trusted-key";

        public const string DescriptionRequireReceipt = "Require an MST transparency receipt in the signature";
        public const string DescriptionMstEndpoint = "MST service endpoint URL for receipt verification";
        public const string DescriptionVerifyReceipt = "Verify the receipt against the MST service (default: true when endpoint provided)";
        public const string DescriptionMstTrustMode = "MST trust mode: online (query endpoint for signing keys) or offline (use a manually provided trust list)";
        public const string DescriptionMstTrustFile = "Offline trust file containing MST signing keys (JSON). Replaces individual --mst-trusted-key entries.";
        public const string DescriptionMstTrustedKey = "Offline trusted signing key entry. Repeatable. Format: <mst-endpoint>=<path-to-jwk-or-jwks-json> (endpoint may be a URL or hostname).";

        public const string TrustModeOnline = "online";
        public const string TrustModeOffline = "offline";

        public const string MetadataKeyReceiptRequired = "Receipt Required";
        public const string MetadataKeyMstEndpoint = "MST Endpoint";
        public const string MetadataKeyVerifyReceipt = "Verify Receipt";
        public const string Yes = "Yes";
        public const string No = "No";

        public const string JsonPropertyKeys = "keys";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 100; // After signature and chain validation

    // Options stored as fields so we can read values from ParseResult
    private Option<bool> RequireReceiptOption = null!;
    private Option<string?> MstEndpointOption = null!;
    private Option<bool> VerifyReceiptOption = null!;

    private Option<string> TrustModeOption = null!;
    private Option<FileInfo?> OfflineTrustFileOption = null!;
    private Option<string[]?> OfflineTrustedKeyOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        RequireReceiptOption = new Option<bool>(
            name: ClassStrings.OptionRequireReceipt,
            description: ClassStrings.DescriptionRequireReceipt);
        command.AddOption(RequireReceiptOption);

        MstEndpointOption = new Option<string?>(
            name: ClassStrings.OptionMstEndpoint,
            description: ClassStrings.DescriptionMstEndpoint);
        command.AddOption(MstEndpointOption);

        VerifyReceiptOption = new Option<bool>(
            name: ClassStrings.OptionVerifyReceipt,
            getDefaultValue: () => true,
            description: ClassStrings.DescriptionVerifyReceipt);
        command.AddOption(VerifyReceiptOption);

        TrustModeOption = new Option<string>(
            name: ClassStrings.OptionMstTrustMode,
            getDefaultValue: () => ClassStrings.TrustModeOnline,
            description: ClassStrings.DescriptionMstTrustMode);
        TrustModeOption.FromAmong(ClassStrings.TrustModeOnline, ClassStrings.TrustModeOffline);
        command.AddOption(TrustModeOption);

        OfflineTrustFileOption = new Option<FileInfo?>(
            name: ClassStrings.OptionMstTrustFile,
            description: ClassStrings.DescriptionMstTrustFile);
        command.AddOption(OfflineTrustFileOption);

        OfflineTrustedKeyOption = new Option<string[]?>(
            name: ClassStrings.OptionMstTrustedKey,
            description: ClassStrings.DescriptionMstTrustedKey)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        command.AddOption(OfflineTrustedKeyOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        return IsReceiptRequired(parseResult)
            || HasMstEndpoint(parseResult)
            || HasOfflineTrustFile(parseResult)
            || HasOfflineTrustedKeys(parseResult);
    }

    /// <inheritdoc/>
    public IEnumerable<IValidationComponent> CreateValidators(ParseResult parseResult)
    {
        var validators = new List<IValidationComponent>();

        bool requireReceipt = IsReceiptRequired(parseResult) || HasMstEndpoint(parseResult);
        bool verifyReceipt = IsVerifyReceipt(parseResult);
        var trustMode = GetTrustMode(parseResult);

        // If the user cares about receipts (presence and/or trust), ensure we emit receipt-present assertions.
        if (requireReceipt)
        {
            validators.Add(new MstReceiptPresenceAssertionProvider());
        }

        // Add receipt verification validator when requested.
        if (verifyReceipt)
        {
            if (trustMode == MstTrustMode.Online)
            {
                // Online: query endpoint for signing keys and validate receipt(s) using returned key(s).
                // This requires an endpoint.
                if (!HasMstEndpoint(parseResult))
                {
                    // No validator: trust policy will fail if receipt trust is required.
                    return validators;
                }

                string endpoint = GetMstEndpoint(parseResult)!;
                var client = new CodeTransparencyClient(new Uri(endpoint));
                validators.Add(new MstReceiptOnlineAssertionProvider(client, issuerHost: new Uri(endpoint).Host));
            }
            else
            {
                // Offline: do not query the endpoint for keys. Use a manually provided trust list.
                // Requires an endpoint (issuer) selection so the trust policy can be explicit.
                if (!HasMstEndpoint(parseResult))
                {
                    return validators;
                }

                string endpoint = GetMstEndpoint(parseResult)!;
                var issuerHost = new Uri(endpoint).Host;

                var offlineKeys = LoadOfflineKeys(parseResult);
                if (offlineKeys == null)
                {
                    return validators;
                }

                var verificationOptions = new CodeTransparencyVerificationOptions
                {
                    OfflineKeys = offlineKeys,
                    OfflineKeysBehavior = OfflineKeysBehavior.NoFallbackToNetwork,
                    AuthorizedDomains = new[] { issuerHost }
                };

                var client = new CodeTransparencyClient(new Uri(endpoint));
                validators.Add(new MstReceiptAssertionProvider(client, verificationOptions));
            }
        }

        // NOTE: Receipt presence is expressed as a trust claim by MstReceiptAssertionProvider.
        // If the CLI requires a receipt, it should express that requirement via the TrustPolicy.

        return validators;
    }

    /// <inheritdoc/>
    public TrustPolicy? CreateTrustPolicy(ParseResult parseResult, VerificationContext context)
    {
        ThrowIfNull(parseResult);

        bool requireReceipt = IsReceiptRequired(parseResult) || HasMstEndpoint(parseResult);
        bool verifyReceipt = IsVerifyReceipt(parseResult);

        // If the MST provider is active at all, we at least require receipt presence.
        // If receipt verification is enabled, require the receipt to be trusted.
        if (requireReceipt && verifyReceipt)
        {
            return MstTrustPolicies.RequireReceiptPresentAndTrusted();
        }

        if (requireReceipt)
        {
            return MstTrustPolicies.RequireReceiptPresent();
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

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult)
    {
        var metadata = new Dictionary<string, object?>
        {
            [ClassStrings.MetadataKeyReceiptRequired] = IsReceiptRequired(parseResult) ? ClassStrings.Yes : ClassStrings.No
        };

        if (HasMstEndpoint(parseResult))
        {
            metadata[ClassStrings.MetadataKeyMstEndpoint] = GetMstEndpoint(parseResult);
            metadata[ClassStrings.MetadataKeyVerifyReceipt] = IsVerifyReceipt(parseResult) ? ClassStrings.Yes : ClassStrings.No;
        }

        return metadata;
    }

    #region Helper Methods

    private bool IsReceiptRequired(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(RequireReceiptOption);
    }

    private bool HasMstEndpoint(ParseResult parseResult)
    {
        var endpoint = parseResult.GetValueForOption(MstEndpointOption);
        return !string.IsNullOrEmpty(endpoint);
    }

    private string? GetMstEndpoint(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(MstEndpointOption);
    }

    private bool IsVerifyReceipt(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(VerifyReceiptOption);
    }

    private MstTrustMode GetTrustMode(ParseResult parseResult)
    {
        var mode = parseResult.GetValueForOption(TrustModeOption);
        return string.Equals(mode, ClassStrings.TrustModeOffline, StringComparison.OrdinalIgnoreCase)
            ? MstTrustMode.Offline
            : MstTrustMode.Online;
    }

    private bool HasOfflineTrustFile(ParseResult parseResult)
    {
        var file = parseResult.GetValueForOption(OfflineTrustFileOption);
        return file != null;
    }

    private bool HasOfflineTrustedKeys(ParseResult parseResult)
    {
        var entries = parseResult.GetValueForOption(OfflineTrustedKeyOption);
        return entries != null && entries.Length > 0;
    }

    private static string NormalizeIssuer(string endpointOrHost)
    {
        if (Uri.TryCreate(endpointOrHost, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        // If it's not a valid absolute URI, treat it as a hostname.
        return endpointOrHost.Trim();
    }

    private CodeTransparencyOfflineKeys? LoadOfflineKeys(ParseResult parseResult)
    {
        // Priority: trust file overrides per-key entries.
        var trustFile = parseResult.GetValueForOption(OfflineTrustFileOption);
        if (trustFile != null)
        {
            if (!trustFile.Exists)
            {
                return null;
            }

            var json = File.ReadAllText(trustFile.FullName, Encoding.UTF8);
            return CodeTransparencyOfflineKeys.FromBinaryData(BinaryData.FromString(json));
        }

        var entries = parseResult.GetValueForOption(OfflineTrustedKeyOption);
        if (entries == null || entries.Length == 0)
        {
            return null;
        }

        // Group keys by issuer host.
        var keysByIssuer = new Dictionary<string, List<JsonElement>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            var idx = entry.IndexOf('=');
            if (idx <= 0 || idx >= entry.Length - 1)
            {
                continue;
            }

            var issuer = NormalizeIssuer(entry.Substring(0, idx));
            var path = entry.Substring(idx + 1);
            if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            if (!File.Exists(path))
            {
                continue;
            }

            var keyJson = File.ReadAllText(path, Encoding.UTF8);
            using var doc = JsonDocument.Parse(keyJson);

            // Accept either a JWKS ({"keys": [...]}) or a single JWK ({"kty":...}).
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (doc.RootElement.TryGetProperty(ClassStrings.JsonPropertyKeys, out var keysElement) && keysElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var key in keysElement.EnumerateArray())
                {
                    if (key.ValueKind == JsonValueKind.Object)
                    {
                        if (!keysByIssuer.TryGetValue(issuer, out var list))
                        {
                            list = new List<JsonElement>();
                            keysByIssuer[issuer] = list;
                        }

                        list.Add(key.Clone());
                    }
                }
            }
            else
            {
                if (!keysByIssuer.TryGetValue(issuer, out var list))
                {
                    list = new List<JsonElement>();
                    keysByIssuer[issuer] = list;
                }

                list.Add(doc.RootElement.Clone());
            }
        }

        if (keysByIssuer.Count == 0)
        {
            return null;
        }

        var offlineKeys = new CodeTransparencyOfflineKeys();
        foreach (var kvp in keysByIssuer)
        {
            var issuer = kvp.Key;
            var keyObjects = kvp.Value;

            // Re-encode as JWKS and let the SDK model deserializer do the rest.
            var jwksJson = JsonSerializer.Serialize(new
            {
                keys = keyObjects
            });

            // JwksDocument is an Azure SDK model that is not generally compatible with
            // System.Text.Json deserialization. Use the SDK's reader/writer instead.
            var jwks = ModelReaderWriter.Read<JwksDocument>(BinaryData.FromString(jwksJson));
            if (jwks == null)
            {
                continue;
            }

            offlineKeys.Add(issuer, jwks);
        }

        return offlineKeys;
    }

    #endregion
}

internal enum MstTrustMode
{
    Online,
    Offline
}