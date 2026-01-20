// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Trust pack for MST.
/// </summary>
public sealed class MstTrustPack : ITrustPack
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DefaultsNotUsed = "MST trust-pack defaults are not used by default";
        public const string NoVetoes = "No MST vetoes";

        public const string MissingMessageCode = "MissingMessage";
        public const string MissingMessage = "COSE message is not available";

        public const string MissingOfflineKeysCode = "MissingOfflineKeys";
        public const string MissingOfflineKeys = "Offline MST signing keys are not supported by this build";

        public const string TrustDetailsOfflineNotImplemented = "OfflineNotImplemented";

        public const string TrustDetailsNoReceipt = "NoReceipt";
        public const string TrustDetailsNotMstReceipt = "NotMstReceipt";
        public const string TrustDetailsVerificationFailed = "VerificationFailed";
        public const string TrustDetailsException = "Exception";

        public const string DetailsSeparator = ": ";

        public const string TrustDetailsOfflineVerification = "OfflineVerification";

        public const string UnsupportedFactTypePrefix = "Unsupported fact type: ";
    }

    private static readonly Type[] SupportedTypes =
    [
        typeof(MstReceiptPresentFact),
        typeof(MstReceiptTrustedFact),
        typeof(MstReceiptIssuerHostFact)
    ];

    private readonly MstTrustOptions Options;
    private readonly ICodeTransparencyVerifier Verifier;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTrustPack"/> class.
    /// </summary>
    /// <param name="options">The MST trust options.</param>
    /// <param name="verifier">Verifier used to validate MST receipts.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public MstTrustPack(MstTrustOptions options, ICodeTransparencyVerifier verifier)
    {
        Guard.ThrowIfNull(options);
        Guard.ThrowIfNull(verifier);
        Options = options;
        Verifier = verifier;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<Type> FactTypes => SupportedTypes;

    /// <inheritdoc />
    public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

    /// <inheritdoc />
    public TrustPlanDefaults GetDefaults()
    {
        return new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.DenyAll(ClassStrings.DefaultsNotUsed) },
            vetoes: TrustRules.DenyAll(ClassStrings.NoVetoes));
    }

    /// <summary>
    /// Produces MST-related trust facts.
    /// </summary>
    /// <param name="context">The trust fact context.</param>
    /// <param name="factType">The fact type to produce.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The produced fact set.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> or <paramref name="factType"/> is null.</exception>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="factType"/> is not supported by this trust pack.</exception>
    public async ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
    {
        Guard.ThrowIfNull(context);
        Guard.ThrowIfNull(factType);

        // These facts are counter-signature scoped.
        if (context.Subject.Kind != TrustSubjectKind.CounterSignature)
        {
            return factType switch
            {
                var t when t == typeof(MstReceiptPresentFact) => TrustFactSet<MstReceiptPresentFact>.Available(),
                var t when t == typeof(MstReceiptTrustedFact) => TrustFactSet<MstReceiptTrustedFact>.Available(),
                var t when t == typeof(MstReceiptIssuerHostFact) => TrustFactSet<MstReceiptIssuerHostFact>.Available(),
                _ => throw new NotSupportedException(string.Concat(ClassStrings.UnsupportedFactTypePrefix, factType)),
            };
        }

        if (factType == typeof(MstReceiptPresentFact))
        {
            if (context.Message == null)
            {
                return TrustFactSet<MstReceiptPresentFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage);
            }

            var isReceipt = IsMstReceiptSubject(context);
            return TrustFactSet<MstReceiptPresentFact>.Available(new MstReceiptPresentFact(isReceipt));
        }

        if (factType == typeof(MstReceiptIssuerHostFact))
        {
            if (context.Message == null)
            {
                return TrustFactSet<MstReceiptIssuerHostFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage);
            }

            if (!TryGetReceiptBytesForSubject(context, out var receiptBytes))
            {
                return TrustFactSet<MstReceiptIssuerHostFact>.Available(new MstReceiptIssuerHostFact(Array.Empty<string>()));
            }

            var hosts = ExtractHostCandidates(receiptBytes);
            if (hosts.Count == 0)
            {
                // Fallback: some real-world statements include the ledger host elsewhere in the message bytes.
                // This remains policy-gated and is only meaningful when combined with MstReceiptTrustedFact.
                hosts = ExtractHostCandidates(context.Message.Encode());
            }
            return TrustFactSet<MstReceiptIssuerHostFact>.Available(new MstReceiptIssuerHostFact(hosts));
        }

        if (factType != typeof(MstReceiptTrustedFact))
        {
            throw new NotSupportedException(string.Concat(ClassStrings.UnsupportedFactTypePrefix, factType));
        }

        if (context.Message == null)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage);
        }

        // If this counter-signature subject is not an MST receipt, it cannot satisfy MST trust.
        if (!IsMstReceiptSubject(context))
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: false, Details: ClassStrings.TrustDetailsNotMstReceipt));
        }

        if (!TryGetReceiptBytesForSubject(context, out var subjectReceiptBytes))
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: false, Details: ClassStrings.TrustDetailsNoReceipt));
        }

        // If receipt verification isn't enabled, we treat trust as unavailable.
        // Policies should not require this fact unless verification is enabled.
        if (!Options.VerifyReceipts)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available();
        }

        // The subject is an MST receipt (as discovered from the message header) so treat "no receipt" as non-applicable.

        // Note: Azure.Security.CodeTransparency (current dependency) does not support providing offline public keys.
        // Verification will download required public keys for each issuer domain encountered.
        if (Options.OfflineOnly)
        {
            if (!Options.HasOfflineKeys)
            {
                return TrustFactSet<MstReceiptTrustedFact>.Missing(ClassStrings.MissingOfflineKeysCode, ClassStrings.MissingOfflineKeys);
            }

            // Offline keys were provided, but full offline verification is not yet implemented.
            // Return an available (but untrusted) fact so callers can distinguish from missing configuration.
            // Attempt offline verification using pinned JWKS JSON.
            try
            {
                var verificationOptionsOffline = MstCodeTransparencyOptions.CreateVerificationOptions(Options);
                var hosts = MstReceiptHostExtractor.ExtractHostCandidates(subjectReceiptBytes);
                if (hosts.Count == 0)
                {
                    hosts = MstReceiptHostExtractor.ExtractHostCandidates(context.Message.Encode());
                }
                MstCodeTransparencyOptions.ConfigureOfflineKeys(verificationOptionsOffline, Options, hosts);

                cancellationToken.ThrowIfCancellationRequested();
                var filtered = MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(context.Message.Encode(), subjectReceiptBytes);
                Verifier.VerifyTransparentStatement(filtered, verificationOptionsOffline, clientOptions: null);

                return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: true, Details: null));
            }
            catch (Exception ex)
            {
                return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(
                    IsTrusted: false,
                    Details: string.Concat(ClassStrings.TrustDetailsException, ClassStrings.DetailsSeparator, ex.GetType().Name, ClassStrings.DetailsSeparator, ex.Message)));
            }
        }

        var verificationOptions = MstCodeTransparencyOptions.CreateVerificationOptions(Options);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var filtered = MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(context.Message.Encode(), subjectReceiptBytes);
            Verifier.VerifyTransparentStatement(filtered, verificationOptions, clientOptions: null);

            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: true, Details: null));
        }
        catch (Exception ex)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(
                IsTrusted: false,
                Details: string.Concat(ClassStrings.TrustDetailsException, ClassStrings.DetailsSeparator, ex.GetType().Name, ClassStrings.DetailsSeparator, ex.Message)));
        }
    }

    private static bool IsMstReceiptSubject(TrustFactContext context)
    {
        if (context.Message == null)
        {
            return false;
        }

        // Receipts are stored in the message header as a list of COSE_Sign1 byte strings.
        foreach (var receiptBytes in context.Message.GetMstReceiptBytes())
        {
            var id = TrustIds.CreateCounterSignatureId(receiptBytes);
            if (id == context.Subject.Id)
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryGetReceiptBytesForSubject(TrustFactContext context, out byte[]? receiptBytes)
    {
        receiptBytes = null;

        if (context.Message == null)
        {
            return false;
        }

        foreach (var bytes in context.Message.GetMstReceiptBytes())
        {
            var id = TrustIds.CreateCounterSignatureId(bytes);
            if (id == context.Subject.Id)
            {
                receiptBytes = bytes;
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<string> ExtractHostCandidates(byte[] receiptBytes)
    {
        return MstReceiptHostExtractor.ExtractHostCandidates(receiptBytes);
    }
}
