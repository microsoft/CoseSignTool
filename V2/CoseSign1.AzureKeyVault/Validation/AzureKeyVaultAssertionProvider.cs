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
public sealed class AzureKeyVaultAssertionProvider : ISigningKeyAssertionProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AzureKeyVaultAssertionProvider);

        public const string NotApplicableReasonNoKid = "Message does not contain a kid header";
        public const string NotApplicableReasonNotAkvKey = "kid does not look like an Azure Key Vault key URI";

        public const string MetadataKeyKid = "kid";
        public const string MetadataKeyMatchedPattern = "matchedPattern";

        public const string TrustDetailsNoPatternMatch = "NoPatternMatch";
        public const string TrustDetailsPatternMatched = "PatternMatched";
        public const string TrustDetailsNoAllowedPatterns = "NoAllowedPatterns";

        public const string KeyVaultHostSuffix = ".vault.azure.net";
        public const string KeyVaultKeysPathFragment = "/keys/";

        public const string RegexPrefix = "regex:";
        public const string RegexWildcard = ".*";
        public const string RegexSingleChar = ".";
        public const string RegexAnchorStart = "^";
        public const string RegexOptionalSuffix = "(/.*)?$";
        public const string UriSchemeHttps = "https";

        // Escaped pattern replacements for glob-to-regex conversion
        public const string EscapedAsterisk = @"\*";
        public const string EscapedQuestionMark = @"\?";
    }

    private static readonly CoseHeaderLabel KidLabel = new(4); // kid header label

    private readonly IReadOnlyList<string> AllowedPatterns;
    private readonly IReadOnlyList<Regex>? CompiledPatterns;
    private readonly bool RequireAzureKeyVaultKey;

    /// <inheritdoc/>
    public string ComponentName => ClassStrings.ValidatorName;

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
        RequireAzureKeyVaultKey = requireAzureKeyVaultKey;

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
    public bool CanProvideAssertions(ISigningKey signingKey)
    {
        // This provider works on message headers, so it can provide assertions for any signing key
        // as long as we have access to the message
        return true;
    }

    /// <inheritdoc/>
    public IReadOnlyList<ISigningKeyAssertion> ExtractAssertions(
        ISigningKey signingKey,
        CoseSign1Message message)
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

        if (RequireAzureKeyVaultKey && !isAkvKey)
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
            new SigningKeyAssertion(AkvTrustClaims.IsAzureKeyVaultKey, isAkvKey),
            new SigningKeyAssertion(AkvTrustClaims.KidAllowed, kidAllowed, details: allowedDetails)
        };
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<ISigningKeyAssertion>> ExtractAssertionsAsync(
        ISigningKey signingKey,
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ExtractAssertions(signingKey, message));
    }

    private static bool TryGetKid(CoseSign1Message message, out string kid)
    {
        kid = string.Empty;

        // Try protected headers first
        if (message.ProtectedHeaders.TryGetValue(KidLabel, out var protectedKid))
        {
            var bytes = protectedKid.GetValueAsBytes();
            if (bytes.Length > 0)
            {
                kid = System.Text.Encoding.UTF8.GetString(bytes);
                return true;
            }
        }

        // Fall back to unprotected headers
        if (message.UnprotectedHeaders.TryGetValue(KidLabel, out var unprotectedKid))
        {
            var bytes = unprotectedKid.GetValueAsBytes();
            if (bytes.Length > 0)
            {
                kid = System.Text.Encoding.UTF8.GetString(bytes);
                return true;
            }
        }

        return false;
    }

    private static bool LooksLikeAzureKeyVaultKeyId(string kid)
    {
        // AKV key ids look like: https://{vault-name}.vault.azure.net/keys/{key-name}[/{version}]
        if (!Uri.TryCreate(kid, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!string.Equals(uri.Scheme, ClassStrings.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!uri.Host.EndsWith(ClassStrings.KeyVaultHostSuffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!uri.AbsolutePath.StartsWith(ClassStrings.KeyVaultKeysPathFragment, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }
}
