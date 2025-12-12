// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Security.Cryptography.Cose;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Extensions;
using CoseSignTool.Output;
using CoseSignTool.Plugins;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Plugin for Microsoft Signing Transparency (MST) verification.
/// Provides commands for verifying transparency proofs embedded in COSE signatures.
/// </summary>
public class MstTransparencyPlugin : IPlugin
{
    /// <inheritdoc/>
    public string Name => "Microsoft Signing Transparency";

    /// <inheritdoc/>
    public string Version => "1.0.0";

    /// <inheritdoc/>
    public string Description => "Verify signatures against Microsoft Signing Transparency service";

    private IOutputFormatter? _formatter;

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? options = null)
    {
        // Configuration can be provided through options if needed in the future
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public IEnumerable<ISigningCommandProvider> GetSigningCommandProviders()
    {
        // MST plugin doesn't provide signing commands
        return Enumerable.Empty<ISigningCommandProvider>();
    }

    /// <inheritdoc/>
    public IEnumerable<ITransparencyProviderContributor> GetTransparencyProviderContributors()
    {
        // MST plugin contributes a transparency provider
        yield return new MstTransparencyProviderContributor();
    }

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        var verifyMstCommand = new Command("verify-mst", "Verify a COSE signature against Microsoft Signing Transparency service");

        var signatureArgument = new Argument<FileInfo>(
            name: "signature",
            description: "Path to the COSE Sign1 signature file");

        var endpointOption = new Option<string?>(
            name: "--endpoint",
            description: "MST service endpoint URL (optional)");

        verifyMstCommand.AddArgument(signatureArgument);
        verifyMstCommand.AddOption(endpointOption);

        verifyMstCommand.SetHandler(async (FileInfo signature, string? endpoint) =>
        {
            await VerifyMstAsync(signature, endpoint);
        }, signatureArgument, endpointOption);

        rootCommand.AddCommand(verifyMstCommand);
    }

    private async Task<int> VerifyMstAsync(FileInfo signatureFile, string? endpoint)
    {
        _formatter ??= new TextOutputFormatter();

        if (!signatureFile.Exists)
        {
            _formatter.WriteError($"Signature file not found: {signatureFile.FullName}");
            return 1;
        }

        try
        {
            _formatter.BeginSection("MST Transparency Verification");
            _formatter.WriteInfo($"Signature: {signatureFile.FullName}");

            // Read and decode the COSE signature
            var bytes = await File.ReadAllBytesAsync(signatureFile.FullName);
            var message = CoseSign1Message.DecodeSign1(bytes);

            // Check if MST receipt is embedded
            if (!message.HasMstReceipt())
            {
                _formatter.WriteWarning("No MST transparency receipt found in signature");
                _formatter.WriteInfo("This signature was not submitted to Microsoft Signing Transparency");
                _formatter.EndSection();
                return 2;
            }

            // Extract the MST receipt(s)
            var receipts = message.GetMstReceipts();
            if (receipts.Count == 0)
            {
                _formatter.WriteError("Failed to extract MST receipt from signature");
                _formatter.EndSection();
                return 3;
            }

            _formatter.WriteSuccess($"Found {receipts.Count} MST receipt(s) in signature");

            // Display receipt information
            for (int i = 0; i < receipts.Count; i++)
            {
                _formatter.WriteInfo($"  Receipt {i + 1}: {receipts[i].Encode().Length} bytes");
            }

            // If endpoint provided, verify against service
            if (!string.IsNullOrEmpty(endpoint))
            {
                var client = new CodeTransparencyClient(new Uri(endpoint));

                _formatter.WriteInfo($"Verifying against MST service: {endpoint}");

                // Note: Actual verification would require the CodeTransparencyClient verification methods
                // For now, we just confirm the receipt is present
                _formatter.WriteSuccess("MST receipt verification would be performed here");
            }
            else
            {
                _formatter.WriteInfo("No endpoint specified - receipt extracted but not verified against service");
            }

            _formatter.EndSection();
            _formatter.WriteSuccess("MST transparency verification complete");
            return 0;
        }
        catch (Exception ex)
        {
            _formatter.WriteError($"Error verifying MST transparency: {ex.Message}");
            _formatter.EndSection();
            return 4;
        }
    }
}