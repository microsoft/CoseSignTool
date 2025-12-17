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

    public void AddVerificationOptions(Command command)
    {
        // No options currently.
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
        return new[]
        {
            new AzureKeyVaultSignatureValidator(context.DetachedPayload)
        };
    }

    public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult)
    {
        return new Dictionary<string, object?>
        {
            ["AKV Key-Only Verification"] = "Enabled"
        };
    }
}
