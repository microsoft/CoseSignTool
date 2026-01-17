// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;

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

        public const string MissingEndpointCode = "MissingEndpoint";
        public const string MissingEndpoint = "MST endpoint is not configured";

        public const string MissingOfflineKeysCode = "MissingOfflineKeys";
        public const string MissingOfflineKeys = "Offline MST signing keys are not supported by this build";

        public const string TrustDetailsOfflineNotImplemented = "OfflineNotImplemented";

        public const string TrustDetailsNoReceipt = "NoReceipt";
        public const string TrustDetailsVerificationFailed = "VerificationFailed";
        public const string TrustDetailsException = "Exception";

        public const string UnsupportedFactTypePrefix = "Unsupported fact type: ";
    }

    private static readonly Type[] SupportedTypes =
    [
        typeof(MstReceiptPresentFact),
        typeof(MstReceiptTrustedFact)
    ];

    private readonly MstTrustOptions Options;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTrustPack"/> class.
    /// </summary>
    /// <param name="options">The MST trust options.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public MstTrustPack(MstTrustOptions options)
    {
        Guard.ThrowIfNull(options);
        Options = options;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<Type> FactTypes => SupportedTypes;

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

        if (factType == typeof(MstReceiptPresentFact))
        {
            if (context.Message == null)
            {
                return TrustFactSet<MstReceiptPresentFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage);
            }

            return TrustFactSet<MstReceiptPresentFact>.Available(new MstReceiptPresentFact(context.Message.HasMstReceipt()));
        }

        if (factType != typeof(MstReceiptTrustedFact))
        {
            throw new NotSupportedException(string.Concat(ClassStrings.UnsupportedFactTypePrefix, factType));
        }

        if (context.Message == null)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Missing(ClassStrings.MissingMessageCode, ClassStrings.MissingMessage);
        }

        // If receipt verification isn't enabled, we treat trust as unavailable.
        // Policies should not require this fact unless verification is enabled.
        if (!Options.VerifyReceipts)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available();
        }

        if (!context.Message.HasMstReceipt())
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: false, Details: ClassStrings.TrustDetailsNoReceipt));
        }

        if (Options.Endpoint == null)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Missing(ClassStrings.MissingEndpointCode, ClassStrings.MissingEndpoint);
        }

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
            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: false, Details: ClassStrings.TrustDetailsOfflineNotImplemented));
        }

        var endpointUri = Options.Endpoint;
        var issuerHost = endpointUri.Host;

        var client = new CodeTransparencyClient(endpointUri);
        var verificationOptions = new CodeTransparencyVerificationOptions
        {
            AuthorizedDomains = new[] { issuerHost },
            UnauthorizedReceiptBehavior = UnauthorizedReceiptBehavior.FailIfPresent
        };

        var provider = new MstTransparencyProvider(client, verificationOptions, clientOptions: null);
        try
        {
            var transparencyResult = await provider.VerifyTransparencyProofAsync(context.Message, cancellationToken)
                .ConfigureAwait(false);

            if (!transparencyResult.IsValid)
            {
                return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: false, Details: ClassStrings.TrustDetailsVerificationFailed));
            }

            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: true, Details: null));
        }
        catch (Exception)
        {
            return TrustFactSet<MstReceiptTrustedFact>.Available(new MstReceiptTrustedFact(IsTrusted: false, Details: ClassStrings.TrustDetailsException));
        }
    }
}
