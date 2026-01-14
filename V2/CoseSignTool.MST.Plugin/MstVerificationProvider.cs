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
public class MstVerificationProvider : IVerificationProvider, IVerificationProviderWithTrustPlanPolicy
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

        public const string ReceiptMustBePresentFailure = "MST receipt must be present";
        public const string ReceiptMustBeVerifiedFailure = "MST receipt must be cryptographically verified";
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
    public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(validationBuilder);
        ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(context);

        bool verifyReceipt = IsVerifyReceipt(parseResult);
        string? endpoint = GetMstEndpoint(parseResult);

        var trustMode = GetTrustMode(parseResult);

        bool hasOfflineKeys = trustMode == MstTrustMode.Offline
            && verifyReceipt
            && (HasValidOfflineTrustFile(parseResult) || HasValidOfflineTrustedKeys(parseResult));

        validationBuilder.EnableMstTrust(trust =>
        {
            // Configure trust pack options to match prior behavior.
            trust.Options.VerifyReceipts = verifyReceipt;

            if (!string.IsNullOrWhiteSpace(endpoint) && Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
            {
                trust.Options.Endpoint = endpointUri;
            }

            if (trustMode == MstTrustMode.Offline)
            {
                trust.OfflineOnly();
            }

            trust.Options.HasOfflineKeys = hasOfflineKeys;
        });
    }

    /// <inheritdoc/>
    public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
    {
        ThrowIfNull(parseResult);

        bool requireReceipt = IsReceiptRequired(parseResult) || HasMstEndpoint(parseResult);
        bool verifyReceipt = IsVerifyReceipt(parseResult);

        if (!requireReceipt)
        {
            return null;
        }

        return TrustPlanPolicy.Message(m =>
        {
            m.RequireFact<MstReceiptPresentFact>(
                f => f.IsPresent,
                ClassStrings.ReceiptMustBePresentFailure);

            if (verifyReceipt)
            {
                m.RequireFact<MstReceiptTrustedFact>(
                    f => f.IsTrusted,
                    ClassStrings.ReceiptMustBeVerifiedFailure);
            }

            return m;
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

    private bool HasValidOfflineTrustFile(ParseResult parseResult)
    {
        var file = parseResult.GetValueForOption(OfflineTrustFileOption);
        if (file == null || !file.Exists)
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(file.FullName));
            return doc.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch
        {
            return false;
        }
    }

    private bool HasValidOfflineTrustedKeys(ParseResult parseResult)
    {
        var entries = parseResult.GetValueForOption(OfflineTrustedKeyOption);
        if (entries == null || entries.Length == 0)
        {
            return false;
        }

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

            var issuer = entry.Substring(0, idx).Trim();
            var path = entry.Substring(idx + 1).Trim();

            if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                // Accept either a JWK (object) or a JWKS ({"keys": [...]})
                if (doc.RootElement.TryGetProperty(ClassStrings.JsonPropertyKeys, out var keys) && keys.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                return true;
            }
            catch
            {
                // Ignore invalid files
            }
        }

        return false;
    }

    #endregion
}

internal enum MstTrustMode
{
    Online,
    Offline
}