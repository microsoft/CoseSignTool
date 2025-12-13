// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using CoseSignTool.Plugins;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Verification provider for Microsoft Signing Transparency (MST) receipt validation.
/// Validates that signatures contain valid SCITT receipts from the MST service.
/// </summary>
public class MstVerificationProvider : IVerificationProvider
{
    /// <inheritdoc/>
    public string ProviderName => "MST";

    /// <inheritdoc/>
    public string Description => "Microsoft Signing Transparency receipt validation";

    /// <inheritdoc/>
    public int Priority => 100; // After signature and chain validation

    // Options stored as fields so we can read values from ParseResult
    private Option<bool> RequireReceiptOption = null!;
    private Option<string?> MstEndpointOption = null!;
    private Option<bool> VerifyReceiptOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        RequireReceiptOption = new Option<bool>(
            name: "--require-receipt",
            description: "Require an MST transparency receipt in the signature");
        command.AddOption(RequireReceiptOption);

        MstEndpointOption = new Option<string?>(
            name: "--mst-endpoint",
            description: "MST service endpoint URL for receipt verification");
        command.AddOption(MstEndpointOption);

        VerifyReceiptOption = new Option<bool>(
            name: "--verify-receipt",
            getDefaultValue: () => true,
            description: "Verify the receipt against the MST service (default: true when endpoint provided)");
        command.AddOption(VerifyReceiptOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        return IsReceiptRequired(parseResult) || HasMstEndpoint(parseResult);
    }

    /// <inheritdoc/>
    public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
    {
        var validators = new List<IValidator<CoseSign1Message>>();

        // Add receipt presence validator if required
        if (IsReceiptRequired(parseResult))
        {
            validators.Add(new MstReceiptPresenceValidator());
        }

        // Add receipt verification validator if endpoint provided
        if (HasMstEndpoint(parseResult) && IsVerifyReceipt(parseResult))
        {
            string endpoint = GetMstEndpoint(parseResult)!;
            var client = new CodeTransparencyClient(new Uri(endpoint));
            var provider = new MstTransparencyProvider(client);
            validators.Add(new MstReceiptValidator(provider));
        }

        return validators;
    }

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult)
    {
        var metadata = new Dictionary<string, object?>
        {
            ["Receipt Required"] = IsReceiptRequired(parseResult) ? "Yes" : "No"
        };

        if (HasMstEndpoint(parseResult))
        {
            metadata["MST Endpoint"] = GetMstEndpoint(parseResult);
            metadata["Verify Receipt"] = IsVerifyReceipt(parseResult) ? "Yes" : "No";
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

    #endregion
}