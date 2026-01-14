// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Trust;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using System.Text;
using System.Text.RegularExpressions;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Trust pack for Azure Key Vault.
/// </summary>
public sealed class AzureKeyVaultTrustPack : ITrustPack
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DefaultsNotUsed = "Azure Key Vault trust-pack defaults are not used by default.";
        public const string NoVetoes = "No AKV vetoes";

        public const string MissingMessageCode = "MissingMessage";
        public const string MissingMessage = "COSE message is not available";

        public const string MissingKidCode = "MissingKid";
        public const string MissingKid = "COSE message does not contain a kid header";

        public const string KeyVaultHostSuffix = ".vault.azure.net";
        public const string KeyVaultKeysPathFragment = "/keys/";

        public const string DetailsNoAllowedPatterns = "NoAllowedPatterns";
        public const string DetailsPatternMatched = "PatternMatched";
        public const string DetailsNoPatternMatch = "NoPatternMatch";

        public const string RegexPrefix = "regex:";
        public const string RegexWildcard = ".*";
        public const string RegexSingleChar = ".";
        public const string RegexAnchorStart = "^";
        public const string RegexOptionalSuffix = "(/.*)?$";

        public const string EscapedAsterisk = @"\*";
        public const string EscapedQuestionMark = @"\?";

        public const string UnsupportedFactTypePrefix = "Unsupported fact type: ";
    }

    private static readonly Type[] SupportedTypes =
    [
        typeof(AzureKeyVaultKidDetectedFact),
        typeof(AzureKeyVaultKidAllowedFact)
    ];

    private static readonly CoseHeaderLabel KidLabel = new(4);

    private readonly AzureKeyVaultTrustOptions Options;
    private readonly IReadOnlyList<Regex>? CompiledPatterns;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultTrustPack"/> class.
    /// </summary>
    /// <param name="options">The Azure Key Vault trust options.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public AzureKeyVaultTrustPack(AzureKeyVaultTrustOptions options)
    {
        Options = options ?? throw new ArgumentNullException(nameof(options));

        var compiled = new List<Regex>();
        foreach (var pattern in Options.AllowedKidPatterns ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(pattern))
            {
                continue;
            }

            if (pattern.StartsWith(ClassStrings.RegexPrefix, StringComparison.OrdinalIgnoreCase))
            {
                compiled.Add(new Regex(pattern.Substring(ClassStrings.RegexPrefix.Length), RegexOptions.Compiled | RegexOptions.IgnoreCase));
                continue;
            }

            var escaped = Regex.Escape(pattern)
                .Replace(ClassStrings.EscapedAsterisk, ClassStrings.RegexWildcard)
                .Replace(ClassStrings.EscapedQuestionMark, ClassStrings.RegexSingleChar);

            compiled.Add(new Regex(
                ClassStrings.RegexAnchorStart + escaped + ClassStrings.RegexOptionalSuffix,
                RegexOptions.Compiled | RegexOptions.IgnoreCase));
        }

        CompiledPatterns = compiled.Count > 0 ? compiled : null;
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<Type> FactTypes => SupportedTypes;

    /// <inheritdoc/>
    public TrustPlanDefaults GetDefaults()
    {
        return new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.DenyAll(ClassStrings.DefaultsNotUsed) },
            vetoes: TrustRules.DenyAll(ClassStrings.NoVetoes));
    }

    /// <summary>
    /// Produces Azure Key Vault kid-related trust facts.
    /// </summary>
    /// <param name="context">The trust fact context.</param>
    /// <param name="factType">The fact type to produce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The produced fact set.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> or <paramref name="factType"/> is null.</exception>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="factType"/> is not supported by this trust pack.</exception>
    public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (factType == null)
        {
            throw new ArgumentNullException(nameof(factType));
        }

        if (context.Message == null)
        {
            if (factType == typeof(AzureKeyVaultKidDetectedFact))
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<AzureKeyVaultKidDetectedFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage));
            }

            if (factType == typeof(AzureKeyVaultKidAllowedFact))
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<AzureKeyVaultKidAllowedFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage));
            }
        }

        if (!TryGetKid(context.Message!, out var kid) || string.IsNullOrWhiteSpace(kid))
        {
            if (factType == typeof(AzureKeyVaultKidDetectedFact))
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<AzureKeyVaultKidDetectedFact>.Missing(ClassStrings.MissingKidCode, ClassStrings.MissingKid));
            }

            if (factType == typeof(AzureKeyVaultKidAllowedFact))
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<AzureKeyVaultKidAllowedFact>.Missing(ClassStrings.MissingKidCode, ClassStrings.MissingKid));
            }
        }

        bool isAkvKey = LooksLikeAzureKeyVaultKeyId(kid);

        if (factType == typeof(AzureKeyVaultKidDetectedFact))
        {
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<AzureKeyVaultKidDetectedFact>.Available(new AzureKeyVaultKidDetectedFact(isAkvKey)));
        }

        if (factType != typeof(AzureKeyVaultKidAllowedFact))
        {
            throw new NotSupportedException(string.Concat(ClassStrings.UnsupportedFactTypePrefix, factType));
        }

        // If the user required an AKV key and this isn't one, this is not allowed.
        if (Options.RequireAzureKeyVaultKid && !isAkvKey)
        {
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<AzureKeyVaultKidAllowedFact>.Available(
                    new AzureKeyVaultKidAllowedFact(false, ClassStrings.DetailsNoPatternMatch)));
        }

        if (CompiledPatterns == null || CompiledPatterns.Count == 0)
        {
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<AzureKeyVaultKidAllowedFact>.Available(
                    new AzureKeyVaultKidAllowedFact(false, ClassStrings.DetailsNoAllowedPatterns)));
        }

        bool matched = CompiledPatterns.Any(p => p.IsMatch(kid));
        return new ValueTask<ITrustFactSet>(
            TrustFactSet<AzureKeyVaultKidAllowedFact>.Available(new AzureKeyVaultKidAllowedFact(
                matched,
                matched ? ClassStrings.DetailsPatternMatched : ClassStrings.DetailsNoPatternMatch)));
    }

    private static bool TryGetKid(CoseSign1Message message, out string kid)
    {
        kid = string.Empty;

        if (message.ProtectedHeaders.TryGetValue(KidLabel, out var protectedKid))
        {
            var bytes = protectedKid.GetValueAsBytes();
            if (bytes.Length > 0)
            {
                kid = Encoding.UTF8.GetString(bytes);
                return true;
            }
        }

        if (message.UnprotectedHeaders.TryGetValue(KidLabel, out var unprotectedKid))
        {
            var bytes = unprotectedKid.GetValueAsBytes();
            if (bytes.Length > 0)
            {
                kid = Encoding.UTF8.GetString(bytes);
                return true;
            }
        }

        return false;
    }

    private static bool LooksLikeAzureKeyVaultKeyId(string? kid)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return false;
        }

        if (!Uri.TryCreate(kid, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Host.EndsWith(ClassStrings.KeyVaultHostSuffix, StringComparison.OrdinalIgnoreCase)
            && uri.AbsolutePath.Contains(ClassStrings.KeyVaultKeysPathFragment, StringComparison.OrdinalIgnoreCase);
    }
}
