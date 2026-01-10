// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using System.Text.RegularExpressions;
using CoseSign1.Abstractions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// A trust-stage validator that checks whether the key identifier (kid) in a COSE_Sign1 message
/// matches allowed Azure Key Vault URI patterns.
/// </summary>
/// <remarks>
/// This validator emits the following trust claims:
/// <list type="bullet">
///   <item><description><c>akv.key.detected</c> - True if the kid looks like an Azure Key Vault key URI</description></item>
///   <item><description><c>akv.kid.allowed</c> - True if the kid matches one of the allowed patterns</description></item>
/// </list>
/// </remarks>
public sealed class AzureKeyVaultAssertionProvider : AkvValidationComponentBase, ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static new class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AzureKeyVaultAssertionProvider);

        public const string NotApplicableReasonNoKid = "Message does not contain a kid header";
        public const string NotApplicableReasonNotAkvKey = "kid does not look like an Azure Key Vault key URI";

        public const string MetadataKeyKid = "kid";
        public const string MetadataKeyMatchedPattern = "matchedPattern";

        public const string TrustDetailsNoPatternMatch = "NoPatternMatch";
        public const string TrustDetailsPatternMatched = "PatternMatched";
        public const string TrustDetailsNoAllowedPatterns = "NoAllowedPatterns";

        public const string RegexPrefix = "regex:";
        public const string RegexWildcard = ".*";
        public const string RegexSingleChar = ".";
        public const string RegexAnchorStart = "^";
        public const string RegexOptionalSuffix = "(/.*)?$";

        // Escaped pattern replacements for glob-to-regex conversion
        public const string EscapedAsterisk = @"\*";
        public const string EscapedQuestionMark = @"\?";
    }

    private readonly IReadOnlyList<string> AllowedPatterns;
    private readonly IReadOnlyList<Regex>? CompiledPatterns;
    private readonly bool _requireAzureKeyVaultKey;

    /// <inheritdoc/>
    public override string ComponentName => ClassStrings.ValidatorName;

    /// <inheritdoc/>
    protected override bool RequireAzureKeyVaultKid => _requireAzureKeyVaultKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultAssertionProvider"/> class.
    /// </summary>
    /// <param name="allowedPatterns">
    /// A list of allowed Key Vault URI patterns. Patterns can be:
    /// <list type="bullet">
    ///   <item><description>Exact URI: <c>https://myvault.vault.azure.net/keys/mykey</c></description></item>
    ///   <item><description>Vault wildcard: <c>https://myvault.vault.azure.net/keys/*</c></description></item>
    ///   <item><description>Full wildcard: <c>https://*.vault.azure.net/keys/*</c></description></item>
    ///   <item><description>Regex pattern (prefix with <c>regex:</c>): <c>regex:https://.*\.vault\.azure\.net/keys/signing-.*</c></description></item>
    /// </list>
    /// If empty or null, only <c>akv.key.detected</c> will be emitted; <c>akv.kid.allowed</c> will be false.
    /// </param>
    /// <param name="requireAzureKeyVaultKey">
    /// If true, this validator is only applicable when the kid looks like an AKV key URI.
    /// If false, the validator runs for any message with a kid header.
    /// </param>
    public AzureKeyVaultAssertionProvider(IEnumerable<string>? allowedPatterns = null, bool requireAzureKeyVaultKey = true)
    {
        AllowedPatterns = allowedPatterns?.ToList() ?? new List<string>();
        _requireAzureKeyVaultKey = requireAzureKeyVaultKey;

        // Pre-compile regex patterns
        var compiled = new List<Regex>();
        foreach (var pattern in AllowedPatterns)
        {
            if (pattern.StartsWith(ClassStrings.RegexPrefix, StringComparison.OrdinalIgnoreCase))
            {
                compiled.Add(new Regex(pattern.Substring(ClassStrings.RegexPrefix.Length), RegexOptions.Compiled | RegexOptions.IgnoreCase));
            }
            else
            {
                // Convert glob-style wildcards to regex
                var escaped = Regex.Escape(pattern)
                    .Replace(ClassStrings.EscapedAsterisk, ClassStrings.RegexWildcard)
                    .Replace(ClassStrings.EscapedQuestionMark, ClassStrings.RegexSingleChar);
                compiled.Add(new Regex(ClassStrings.RegexAnchorStart + escaped + ClassStrings.RegexOptionalSuffix, RegexOptions.Compiled | RegexOptions.IgnoreCase));
            }
        }

        CompiledPatterns = compiled.Count > 0 ? compiled : null;
    }

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null)
    {
        if (message == null)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        if (!TryGetKid(message, out var kid) || string.IsNullOrWhiteSpace(kid))
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        bool isAkvKey = LooksLikeAzureKeyVaultKeyId(kid);

        if (_requireAzureKeyVaultKey && !isAkvKey)
        {
            return Array.Empty<ISigningKeyAssertion>();
        }

        // Check if kid matches any allowed pattern
        bool kidAllowed = false;
        string allowedDetails;

        if (CompiledPatterns == null || CompiledPatterns.Count == 0)
        {
            allowedDetails = ClassStrings.TrustDetailsNoAllowedPatterns;
        }
        else
        {
            for (int i = 0; i < CompiledPatterns.Count; i++)
            {
                if (CompiledPatterns[i].IsMatch(kid))
                {
                    kidAllowed = true;
                    break;
                }
            }

            allowedDetails = kidAllowed 
                ? ClassStrings.TrustDetailsPatternMatched 
                : ClassStrings.TrustDetailsNoPatternMatch;
        }

        return new ISigningKeyAssertion[]
        {
            new AkvKeyDetectedAssertion(isAkvKey),
            new AkvKidAllowedAssertion(kidAllowed, allowedDetails)
        };
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CoseSign1ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ExtractAssertions(signingKey, message, options));
    }
}
