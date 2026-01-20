// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts.Producers;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Trust pack that produces typed X.509 certificate facts from COSE headers.
/// Applies to certificate-based signing keys (primary signing key and counter-signature signing keys).
/// </summary>
public sealed partial class X509CertificateTrustPack : ITrustPack
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MissingMessageUnavailableSigningCertificate = "COSE message is not available for signing certificate discovery";
        public const string MissingMessageUnavailableX5Chain = "COSE message is not available for x5chain discovery";
        public const string MissingSigningCertificateNotFound = "Signing certificate not available from x5t/x5chain";
        public const string MissingX5ChainNotFound = "Certificate chain not available from x5chain";

        public const string ProducerFailedIdentity = "Failed to extract signing certificate identity";
        public const string ProducerFailedEku = "Failed to extract signing certificate EKU";
        public const string ProducerFailedKeyUsage = "Failed to extract signing certificate key usage";
        public const string ProducerFailedBasicConstraints = "Failed to extract signing certificate basic constraints";
        public const string ProducerFailedX5ChainIdentities = "Failed to extract x5chain certificate identities";

        public const string ProducerFailedChainTrust = "Failed to evaluate signing certificate chain trust";

        public const string MissingTrustSourceNotConfigured = "Certificate trust source not configured";
        public const string MissingIdentityConstraintsNotConfigured = "Certificate identity allow-list not configured";
        public const string MissingNoX5ChainForChainElementFacts = "Certificate chain not available from x5chain";

        public const string ErrorUnsupportedFactType = "Unsupported fact type requested";

        public const string TrustDefaultsNotConfigured = "Certificate trust defaults not configured";
        public const string NoVetoes = "No certificate vetoes";

        public const string DefaultRequireTrustedChain = "Primary certificate chain must be trusted";
        public const string DefaultRequireAllowedIdentity = "Primary certificate identity is not allowed";

        public const string ChainStatusSeparator = "; ";
        public const string CertificateChainValidationFailed = "Certificate chain validation failed";
    }

    private readonly CertificateTrustBuilder.CertificateTrustOptions Options;

    /// <inheritdoc />
    public ISigningKeyResolver? SigningKeyResolver => null;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificateTrustPack"/> class.
    /// </summary>
    public X509CertificateTrustPack()
    {
        Options = new CertificateTrustBuilder.CertificateTrustOptions();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificateTrustPack"/> class.
    /// </summary>
    /// <param name="options">Certificate trust options.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public X509CertificateTrustPack(CertificateTrustBuilder.CertificateTrustOptions options)
    {
        Guard.ThrowIfNull(options);
        Options = options;
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 6200,
        Level = LogLevel.Trace,
        Message = "Producing certificate fact. FactType: {FactType}, SubjectKind: {SubjectKind}")]
    private static partial void LogProducing(ILogger logger, string factType, TrustSubjectKind subjectKind);

    [LoggerMessage(
        EventId = 6201,
        Level = LogLevel.Debug,
        Message = "Certificate fact cache hit. FactType: {FactType}")]
    private static partial void LogCacheHit(ILogger logger, string factType);

    [LoggerMessage(
        EventId = 6202,
        Level = LogLevel.Debug,
        Message = "Certificate fact not applicable for subject kind. FactType: {FactType}, SubjectKind: {SubjectKind}")]
    private static partial void LogNotApplicable(ILogger logger, string factType, TrustSubjectKind subjectKind);

    [LoggerMessage(
        EventId = 6203,
        Level = LogLevel.Debug,
        Message = "COSE message unavailable; returning missing certificate fact. FactType: {FactType}")]
    private static partial void LogMessageUnavailable(ILogger logger, string factType);

    [LoggerMessage(
        EventId = 6204,
        Level = LogLevel.Debug,
        Message = "Unsupported fact type requested by engine. FactType: {FactType}")]
    private static partial void LogUnsupportedFactType(ILogger logger, string factType);

    [LoggerMessage(
        EventId = 6205,
        Level = LogLevel.Debug,
        Message = "Signing certificate not found in COSE headers")]
    private static partial void LogSigningCertificateNotFound(ILogger logger);

    [LoggerMessage(
        EventId = 6206,
        Level = LogLevel.Debug,
        Message = "x5chain not found in COSE headers")]
    private static partial void LogX5ChainNotFound(ILogger logger);

    [LoggerMessage(
        EventId = 6207,
        Level = LogLevel.Error,
        Message = "Certificate fact producer failed. FactType: {FactType}")]
    private static partial void LogProducerFailed(ILogger logger, Exception ex, string factType);

    #endregion

    private static readonly Type[] SupportedTypes =
    [
        typeof(X509SigningCertificateIdentityFact),
        typeof(X509SigningCertificateIdentityAllowedFact),
        typeof(X509SigningCertificateEkuFact),
        typeof(X509SigningCertificateKeyUsageFact),
        typeof(X509SigningCertificateBasicConstraintsFact),
        typeof(X509X5ChainCertificateIdentityFact),
        typeof(X509ChainTrustedFact),
        typeof(X509ChainElementIdentityFact),
        typeof(CertificateSigningKeyTrustFact),
    ];

    /// <inheritdoc />
    public IReadOnlyCollection<Type> FactTypes => SupportedTypes;

    /// <inheritdoc />
    public TrustPlanDefaults GetDefaults()
    {
        // Defaults only apply when the pack is configured.
        // If configuration is incomplete, defaults deny with actionable reasons.

        if (Options.SourceKind == CertificateTrustSourceKind.None)
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll(ClassStrings.MissingTrustSourceNotConfigured) },
                vetoes: TrustRules.DenyAll(ClassStrings.NoVetoes));
        }

        if (Options.IdentityPinningEnabled && Options.AllowedThumbprints.Count == 0 && Options.AllowedSubjectIssuerPatterns.Count == 0)
        {
            return new TrustPlanDefaults(
                constraints: TrustRules.AllowAll(),
                trustSources: new[] { TrustRules.DenyAll(ClassStrings.MissingIdentityConstraintsNotConfigured) },
                vetoes: TrustRules.DenyAll(ClassStrings.NoVetoes));
        }

        var requireTrustedChain = TrustRules.AnyFact<X509ChainTrustedFact>(
            f => f.IsTrusted,
            missingFactMessage: ClassStrings.DefaultRequireTrustedChain,
            predicateFailedMessage: ClassStrings.DefaultRequireTrustedChain,
            onEmpty: OnEmptyBehavior.Deny,
            onEmptyMessage: ClassStrings.DefaultRequireTrustedChain);

        TrustRule requireAllowedIdentity = TrustRules.AnyFact<X509SigningCertificateIdentityAllowedFact>(
            f => f.IsAllowed,
            missingFactMessage: ClassStrings.DefaultRequireAllowedIdentity,
            predicateFailedMessage: ClassStrings.DefaultRequireAllowedIdentity,
            onEmpty: OnEmptyBehavior.Deny,
            onEmptyMessage: ClassStrings.DefaultRequireAllowedIdentity);

        TrustRule combinedRule = Options.IdentityPinningEnabled
            ? TrustRules.And(requireTrustedChain, requireAllowedIdentity)
            : requireTrustedChain;

        var defaultTrustSource = TrustRules.OnDerivedSubject(
            expectedSubjectKind: TrustSubjectKind.Message,
            deriveSubject: ctx => TrustSubject.PrimarySigningKey(ctx.Facts.MessageId),
            inner: combinedRule);

        return new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { defaultTrustSource },
            vetoes: TrustRules.DenyAll(ClassStrings.NoVetoes));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> or <paramref name="factType"/> is null.</exception>
    public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
    {
        Guard.ThrowIfNull(context);
        Guard.ThrowIfNull(factType);

        ILogger logger = ResolveLogger(context);
        LogProducing(logger, factType.FullName ?? factType.Name, context.Subject.Kind);

        if (context.Subject.Kind != TrustSubjectKind.PrimarySigningKey
            && context.Subject.Kind != TrustSubjectKind.CounterSignatureSigningKey)
        {
            LogNotApplicable(logger, factType.FullName ?? factType.Name, context.Subject.Kind);

            return factType switch
            {
                var t when t == typeof(X509SigningCertificateIdentityFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509SigningCertificateIdentityFact>.Available()),
                var t when t == typeof(X509SigningCertificateIdentityAllowedFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509SigningCertificateIdentityAllowedFact>.Available()),
                var t when t == typeof(X509SigningCertificateEkuFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509SigningCertificateEkuFact>.Available()),
                var t when t == typeof(X509SigningCertificateKeyUsageFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509SigningCertificateKeyUsageFact>.Available()),
                var t when t == typeof(X509SigningCertificateBasicConstraintsFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509SigningCertificateBasicConstraintsFact>.Available()),
                var t when t == typeof(X509X5ChainCertificateIdentityFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509X5ChainCertificateIdentityFact>.Available()),
                var t when t == typeof(X509ChainTrustedFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509ChainTrustedFact>.Available()),
                var t when t == typeof(X509ChainElementIdentityFact) => new ValueTask<ITrustFactSet>(TrustFactSet<X509ChainElementIdentityFact>.Available()),
                var t when t == typeof(CertificateSigningKeyTrustFact) => new ValueTask<ITrustFactSet>(TrustFactSet<CertificateSigningKeyTrustFact>.Available()),
                _ => new ValueTask<ITrustFactSet>(TrustFactSet<object>.Missing(TrustFactMissingCodes.InputUnavailable, ClassStrings.ErrorUnsupportedFactType)),
            };
        }

        if (context.Message == null)
        {
            LogMessageUnavailable(logger, factType.FullName ?? factType.Name);

            return factType switch
            {
                var t when t == typeof(X509X5ChainCertificateIdentityFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509X5ChainCertificateIdentityFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableX5Chain)),
                var t when t == typeof(X509SigningCertificateIdentityFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateIdentityFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableSigningCertificate)),
                var t when t == typeof(X509SigningCertificateIdentityAllowedFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateIdentityAllowedFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableSigningCertificate)),
                var t when t == typeof(X509SigningCertificateEkuFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateEkuFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableSigningCertificate)),
                var t when t == typeof(X509SigningCertificateKeyUsageFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateKeyUsageFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableSigningCertificate)),
                var t when t == typeof(X509SigningCertificateBasicConstraintsFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateBasicConstraintsFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableSigningCertificate)),
                var t when t == typeof(X509ChainTrustedFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509ChainTrustedFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableX5Chain)),
                var t when t == typeof(X509ChainElementIdentityFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509ChainElementIdentityFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableX5Chain)),
                var t when t == typeof(CertificateSigningKeyTrustFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<CertificateSigningKeyTrustFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailableX5Chain)),
                _ => new ValueTask<ITrustFactSet>(
                    TrustFactSet<object>.Missing(TrustFactMissingCodes.InputUnavailable, ClassStrings.ErrorUnsupportedFactType)),
            };
        }

        return factType switch
        {
            var t when t == typeof(X509SigningCertificateIdentityFact) => ProduceSigningCertificateIdentity(context, logger),
            var t when t == typeof(X509SigningCertificateIdentityAllowedFact) => ProduceSigningCertificateIdentityAllowed(context, logger),
            var t when t == typeof(X509SigningCertificateEkuFact) => ProduceSigningCertificateEku(context, logger),
            var t when t == typeof(X509SigningCertificateKeyUsageFact) => ProduceSigningCertificateKeyUsage(context, logger),
            var t when t == typeof(X509SigningCertificateBasicConstraintsFact) => ProduceSigningCertificateBasicConstraints(context, logger),
            var t when t == typeof(X509X5ChainCertificateIdentityFact) => ProduceX5ChainIdentities(context, logger),
            var t when t == typeof(X509ChainTrustedFact) => ProduceChainTrusted(context, logger),
            var t when t == typeof(X509ChainElementIdentityFact) => ProduceChainElementIdentities(context, logger),
            var t when t == typeof(CertificateSigningKeyTrustFact) => ProduceCertificateSigningKeyTrust(context, logger),
            _ => UnsupportedFactType(factType, logger),
        };
    }

    private sealed class ChainEvaluationCacheMarker
    {
    }

    private sealed class ChainEvaluationResult
    {
        public ChainEvaluationResult(
            bool SigningCertificateFound,
            string? Thumbprint,
            string? Subject,
            string? Issuer,
            bool ChainBuilt,
            bool ChainTrusted,
            X509ChainStatusFlags ChainStatusFlags,
            string? ChainStatusSummary,
            IReadOnlyList<X509ChainElementIdentityFact> ElementIdentities,
            bool IdentityAllowed)
        {
            Guard.ThrowIfNull(ElementIdentities);

            this.SigningCertificateFound = SigningCertificateFound;
            this.Thumbprint = Thumbprint;
            this.Subject = Subject;
            this.Issuer = Issuer;
            this.ChainBuilt = ChainBuilt;
            this.ChainTrusted = ChainTrusted;
            this.ChainStatusFlags = ChainStatusFlags;
            this.ChainStatusSummary = ChainStatusSummary;
            this.ElementIdentities = ElementIdentities;
            this.IdentityAllowed = IdentityAllowed;
        }

        public bool SigningCertificateFound { get; }

        public string? Thumbprint { get; }

        public string? Subject { get; }

        public string? Issuer { get; }

        public bool ChainBuilt { get; }

        public bool ChainTrusted { get; }

        public X509ChainStatusFlags ChainStatusFlags { get; }

        public string? ChainStatusSummary { get; }

        public IReadOnlyList<X509ChainElementIdentityFact> ElementIdentities { get; }

        public bool IdentityAllowed { get; }
    }

    private ChainEvaluationResult EvaluateChain(TrustFactContext context)
    {
        // Cache the expensive chain build across multiple fact type requests.
        var cacheKey = context.CreateCacheKey(typeof(ChainEvaluationCacheMarker));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out ChainEvaluationResult? cached) &&
            cached != null)
        {
            return cached;
        }

        try
        {
            var message = context.Message!;

            if (!message.TryGetSigningCertificate(out var signingCertificate, CoseHeaderLocation.Any) || signingCertificate == null)
            {
                var missing = new ChainEvaluationResult(
                    SigningCertificateFound: false,
                    Thumbprint: null,
                    Subject: null,
                    Issuer: null,
                    ChainBuilt: false,
                    ChainTrusted: false,
                    ChainStatusFlags: X509ChainStatusFlags.NoError,
                    ChainStatusSummary: null,
                    ElementIdentities: Array.Empty<X509ChainElementIdentityFact>(),
                    IdentityAllowed: false);

                context.MemoryCache?.Set(cacheKey, missing);
                return missing;
            }

            var thumbprint = signingCertificate.GetCertHashString();
            var subject = signingCertificate.Subject;
            var issuer = signingCertificate.Issuer;

            // Always attempt to surface chain element identities.
            // Prefer built chain elements when available; fall back to x5chain header order.
            var elementFacts = new List<X509ChainElementIdentityFact>();

            bool chainBuilt = false;
            bool chainTrusted = false;
            X509ChainStatusFlags combinedStatusFlags = X509ChainStatusFlags.NoError;
            string? summary = null;

            int elementCount = 0;

            if (Options.SourceKind != CertificateTrustSourceKind.None)
            {
                using var x509Chain = new X509Chain
                {
                    ChainPolicy =
                    {
                        RevocationMode = Options.RevocationMode,
                        RevocationFlag = Options.RevocationFlag,
                        VerificationFlags = Options.VerificationFlags,
                    }
                };

                if (message.TryGetCertificateChain(out var headerChain, CoseHeaderLocation.Any) && headerChain != null && headerChain.Count > 0)
                {
                    x509Chain.ChainPolicy.ExtraStore.AddRange(headerChain);
                }

                if (message.TryGetExtraCertificates(out var extraCerts, CoseHeaderLocation.Any) && extraCerts != null && extraCerts.Count > 0)
                {
                    x509Chain.ChainPolicy.ExtraStore.AddRange(extraCerts);
                }

#if NET5_0_OR_GREATER
                switch (Options.SourceKind)
                {
                    case CertificateTrustSourceKind.System:
                        x509Chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
                        break;
                    case CertificateTrustSourceKind.CustomRoot:
                        x509Chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        x509Chain.ChainPolicy.CustomTrustStore.Clear();
                        x509Chain.ChainPolicy.CustomTrustStore.AddRange(Options.CustomTrustRoots);
                        break;
                    case CertificateTrustSourceKind.EmbeddedChainOnly:
                        x509Chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        x509Chain.ChainPolicy.CustomTrustStore.Clear();
                        // Embedded-chain-only scenarios typically rely on identity pinning; allow unknown roots.
                        x509Chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;
                        break;
                }
#endif

                chainBuilt = x509Chain.Build(signingCertificate);
                elementCount = x509Chain.ChainElements.Count;

                combinedStatusFlags = x509Chain.ChainStatus.Aggregate(
                    X509ChainStatusFlags.NoError,
                    (acc, s) => acc | s.Status);

                chainTrusted = chainBuilt && IsChainTrustedPerSource(Options.SourceKind, x509Chain.ChainStatus);

                if (!chainTrusted)
                {
                    summary = string.Join(ClassStrings.ChainStatusSeparator, x509Chain.ChainStatus
                        .Where(s => s.Status != X509ChainStatusFlags.NoError)
                        .Select(s => s.StatusInformation.Trim())
                        .Where(s => !string.IsNullOrWhiteSpace(s)));

                    if (string.IsNullOrWhiteSpace(summary))
                    {
                        summary = ClassStrings.CertificateChainValidationFailed;
                    }
                }

                if (x509Chain.ChainElements.Count > 0)
                {
                    var chainLength = x509Chain.ChainElements.Count;
                    for (int i = 0; i < chainLength; i++)
                    {
                        var cert = x509Chain.ChainElements[i].Certificate;
                        elementFacts.Add(new X509ChainElementIdentityFact(
                            depth: i,
                            chainLength: chainLength,
                            certificateThumbprint: cert.GetCertHashString(),
                            subject: cert.Subject,
                            issuer: cert.Issuer,
                            serialNumber: cert.SerialNumber,
                            notBefore: cert.NotBefore,
                            notAfter: cert.NotAfter));
                    }
                }
            }

            if (elementFacts.Count == 0)
            {
                if (message.TryGetCertificateChain(out var headerChain, CoseHeaderLocation.Any) && headerChain != null && headerChain.Count > 0)
                {
                    var chainLength = headerChain.Count;
                    for (int i = 0; i < chainLength; i++)
                    {
                        var cert = headerChain[i];
                        elementFacts.Add(new X509ChainElementIdentityFact(
                            depth: i,
                            chainLength: chainLength,
                            certificateThumbprint: cert.GetCertHashString(),
                            subject: cert.Subject,
                            issuer: cert.Issuer,
                            serialNumber: cert.SerialNumber,
                            notBefore: cert.NotBefore,
                            notAfter: cert.NotAfter));
                    }

                    elementCount = chainLength;
                }
            }

            bool identityAllowed = Options.IsIdentityAllowed(thumbprint, subject, issuer);

            var result = new ChainEvaluationResult(
                SigningCertificateFound: true,
                Thumbprint: thumbprint,
                Subject: subject,
                Issuer: issuer,
                ChainBuilt: chainBuilt,
                ChainTrusted: chainTrusted,
                ChainStatusFlags: combinedStatusFlags,
                ChainStatusSummary: summary,
                ElementIdentities: elementFacts,
                IdentityAllowed: identityAllowed);

            context.MemoryCache?.Set(cacheKey, result);
            return result;
        }
        catch
        {
            // Treat any unexpected errors as a missing chain trust fact.
            // The exception is captured by the caller in its missing reason.
            throw;
        }
    }

    private static bool IsChainTrustedPerSource(CertificateTrustSourceKind kind, X509ChainStatus[] statuses)
    {
        if (statuses == null || statuses.Length == 0)
        {
            return true;
        }

        return kind switch
        {
            CertificateTrustSourceKind.EmbeddedChainOnly => statuses.All(s => s.Status == X509ChainStatusFlags.NoError || s.Status == X509ChainStatusFlags.UntrustedRoot),
            _ => statuses.All(s => s.Status == X509ChainStatusFlags.NoError),
        };
    }

    private ValueTask<ITrustFactSet> ProduceChainTrusted(TrustFactContext context, ILogger logger)
    {
        var cacheKey = context.CreateCacheKey(typeof(X509ChainTrustedFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509ChainTrustedFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509ChainTrustedFact).FullName ?? nameof(X509ChainTrustedFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            if (Options.SourceKind == CertificateTrustSourceKind.None)
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509ChainTrustedFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingTrustSourceNotConfigured));
            }

            var result = EvaluateChain(context);
            if (!result.SigningCertificateFound)
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509ChainTrustedFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            var fact = new X509ChainTrustedFact(
                chainBuilt: result.ChainBuilt,
                isTrusted: result.ChainTrusted,
                statusFlags: result.ChainStatusFlags,
                statusSummary: result.ChainStatusSummary,
                elementCount: result.ElementIdentities.Count);

            var set = TrustFactSet<X509ChainTrustedFact>.Available(fact);
            context.MemoryCache?.Set(cacheKey, set);
            return new ValueTask<ITrustFactSet>(set);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509ChainTrustedFact).FullName ?? nameof(X509ChainTrustedFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509ChainTrustedFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedChainTrust,
                    ex));
        }
    }

    private ValueTask<ITrustFactSet> ProduceCertificateSigningKeyTrust(TrustFactContext context, ILogger logger)
    {
        var cacheKey = context.CreateCacheKey(typeof(CertificateSigningKeyTrustFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<CertificateSigningKeyTrustFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(CertificateSigningKeyTrustFact).FullName ?? nameof(CertificateSigningKeyTrustFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            var result = EvaluateChain(context);
            if (!result.SigningCertificateFound || result.Thumbprint == null || result.Subject == null || result.Issuer == null)
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<CertificateSigningKeyTrustFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            var fact = new CertificateSigningKeyTrustFact(
                thumbprint: result.Thumbprint,
                subject: result.Subject,
                issuer: result.Issuer,
                chainBuilt: result.ChainBuilt,
                chainTrusted: result.ChainTrusted,
                chainStatusFlags: result.ChainStatusFlags,
                chainStatusSummary: result.ChainStatusSummary);

            var set = TrustFactSet<CertificateSigningKeyTrustFact>.Available(fact);
            context.MemoryCache?.Set(cacheKey, set);
            return new ValueTask<ITrustFactSet>(set);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(CertificateSigningKeyTrustFact).FullName ?? nameof(CertificateSigningKeyTrustFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<CertificateSigningKeyTrustFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedChainTrust,
                    ex));
        }
    }

    private ValueTask<ITrustFactSet> ProduceChainElementIdentities(TrustFactContext context, ILogger logger)
    {
        var cacheKey = context.CreateCacheKey(typeof(X509ChainElementIdentityFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509ChainElementIdentityFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509ChainElementIdentityFact).FullName ?? nameof(X509ChainElementIdentityFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            var result = EvaluateChain(context);
            if (result.ElementIdentities.Count == 0)
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509ChainElementIdentityFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingNoX5ChainForChainElementFacts));
            }

            var set = TrustFactSet<X509ChainElementIdentityFact>.Available(result.ElementIdentities.ToArray());
            context.MemoryCache?.Set(cacheKey, set);
            return new ValueTask<ITrustFactSet>(set);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509ChainElementIdentityFact).FullName ?? nameof(X509ChainElementIdentityFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509ChainElementIdentityFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedChainTrust,
                    ex));
        }
    }

    private ValueTask<ITrustFactSet> ProduceSigningCertificateIdentityAllowed(TrustFactContext context, ILogger logger)
    {
        var cacheKey = context.CreateCacheKey(typeof(X509SigningCertificateIdentityAllowedFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509SigningCertificateIdentityAllowedFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509SigningCertificateIdentityAllowedFact).FullName ?? nameof(X509SigningCertificateIdentityAllowedFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            var result = EvaluateChain(context);
            if (!result.SigningCertificateFound || result.Thumbprint == null || result.Subject == null || result.Issuer == null)
            {
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateIdentityAllowedFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            var fact = new X509SigningCertificateIdentityAllowedFact(
                certificateThumbprint: result.Thumbprint,
                subject: result.Subject,
                issuer: result.Issuer,
                isAllowed: result.IdentityAllowed);

            var set = TrustFactSet<X509SigningCertificateIdentityAllowedFact>.Available(fact);
            context.MemoryCache?.Set(cacheKey, set);
            return new ValueTask<ITrustFactSet>(set);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509SigningCertificateIdentityAllowedFact).FullName ?? nameof(X509SigningCertificateIdentityAllowedFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509SigningCertificateIdentityAllowedFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedIdentity,
                    ex));
        }
    }

    private static ValueTask<ITrustFactSet> UnsupportedFactType(Type factType, ILogger logger)
    {
        LogUnsupportedFactType(logger, factType.FullName ?? factType.Name);
        return new ValueTask<ITrustFactSet>(
            TrustFactSet<object>.Missing(TrustFactMissingCodes.InputUnavailable, ClassStrings.ErrorUnsupportedFactType));
    }

    private static ILogger ResolveLogger(TrustFactContext context)
    {
        if (context.Services == null)
        {
            return NullLogger.Instance;
        }

        return (context.Services.GetService(typeof(ILogger<X509CertificateTrustPack>)) as ILogger<X509CertificateTrustPack>)
            ?? NullLogger<X509CertificateTrustPack>.Instance;
    }

    private static ValueTask<ITrustFactSet> ProduceSigningCertificateIdentity(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(X509SigningCertificateIdentityFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509SigningCertificateIdentityFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509SigningCertificateIdentityFact).FullName ?? nameof(X509SigningCertificateIdentityFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            if (!context.Message!.TryGetSigningCertificate(out X509Certificate2? signingCertificate, CoseHeaderLocation.Any) || signingCertificate == null)
            {
                LogSigningCertificateNotFound(logger);
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateIdentityFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            var fact = new X509SigningCertificateIdentityFact(
                certificateThumbprint: signingCertificate.GetCertHashString(),
                subject: signingCertificate.Subject,
                issuer: signingCertificate.Issuer,
                serialNumber: signingCertificate.SerialNumber,
                notBefore: signingCertificate.NotBefore,
                notAfter: signingCertificate.NotAfter);

            var result = TrustFactSet<X509SigningCertificateIdentityFact>.Available(fact);
            context.MemoryCache?.Set(cacheKey, result);
            return new ValueTask<ITrustFactSet>(result);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509SigningCertificateIdentityFact).FullName ?? nameof(X509SigningCertificateIdentityFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509SigningCertificateIdentityFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedIdentity,
                    ex));
        }
    }

    private static ValueTask<ITrustFactSet> ProduceSigningCertificateEku(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(X509SigningCertificateEkuFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509SigningCertificateEkuFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509SigningCertificateEkuFact).FullName ?? nameof(X509SigningCertificateEkuFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            if (!context.Message!.TryGetSigningCertificate(out X509Certificate2? signingCertificate, CoseHeaderLocation.Any) || signingCertificate == null)
            {
                LogSigningCertificateNotFound(logger);
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateEkuFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            var facts = new List<X509SigningCertificateEkuFact>();
            string certificateThumbprint = signingCertificate.GetCertHashString();
            foreach (X509Extension extension in signingCertificate.Extensions)
            {
                if (extension is X509EnhancedKeyUsageExtension eku)
                {
                    foreach (Oid? oid in eku.EnhancedKeyUsages)
                    {
                        if (!string.IsNullOrEmpty(oid?.Value))
                        {
                            facts.Add(new X509SigningCertificateEkuFact(certificateThumbprint, oid.Value));
                        }
                    }
                }
            }

            var result = TrustFactSet<X509SigningCertificateEkuFact>.Available(facts.ToArray());
            context.MemoryCache?.Set(cacheKey, result);
            return new ValueTask<ITrustFactSet>(result);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509SigningCertificateEkuFact).FullName ?? nameof(X509SigningCertificateEkuFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509SigningCertificateEkuFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedEku,
                    ex));
        }
    }

    private static ValueTask<ITrustFactSet> ProduceSigningCertificateKeyUsage(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(X509SigningCertificateKeyUsageFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509SigningCertificateKeyUsageFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509SigningCertificateKeyUsageFact).FullName ?? nameof(X509SigningCertificateKeyUsageFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            if (!context.Message!.TryGetSigningCertificate(out X509Certificate2? signingCertificate, CoseHeaderLocation.Any) || signingCertificate == null)
            {
                LogSigningCertificateNotFound(logger);
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateKeyUsageFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            foreach (X509Extension extension in signingCertificate.Extensions)
            {
                if (extension is X509KeyUsageExtension keyUsage)
                {
                    var resultWithValue = TrustFactSet<X509SigningCertificateKeyUsageFact>.Available(
                        new X509SigningCertificateKeyUsageFact(signingCertificate.GetCertHashString(), keyUsage.KeyUsages));

                    context.MemoryCache?.Set(cacheKey, resultWithValue);
                    return new ValueTask<ITrustFactSet>(resultWithValue);
                }
            }

            var result = TrustFactSet<X509SigningCertificateKeyUsageFact>.Available();
            context.MemoryCache?.Set(cacheKey, result);
            return new ValueTask<ITrustFactSet>(result);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509SigningCertificateKeyUsageFact).FullName ?? nameof(X509SigningCertificateKeyUsageFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509SigningCertificateKeyUsageFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedKeyUsage,
                    ex));
        }
    }

    private static ValueTask<ITrustFactSet> ProduceSigningCertificateBasicConstraints(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(X509SigningCertificateBasicConstraintsFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509SigningCertificateBasicConstraintsFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509SigningCertificateBasicConstraintsFact).FullName ?? nameof(X509SigningCertificateBasicConstraintsFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            if (!context.Message!.TryGetSigningCertificate(out X509Certificate2? signingCertificate, CoseHeaderLocation.Any) || signingCertificate == null)
            {
                LogSigningCertificateNotFound(logger);
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509SigningCertificateBasicConstraintsFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingSigningCertificateNotFound));
            }

            foreach (X509Extension extension in signingCertificate.Extensions)
            {
                if (extension is X509BasicConstraintsExtension constraints)
                {
                    var fact = new X509SigningCertificateBasicConstraintsFact(
                        certificateThumbprint: signingCertificate.GetCertHashString(),
                        certificateAuthority: constraints.CertificateAuthority,
                        hasPathLengthConstraint: constraints.HasPathLengthConstraint,
                        pathLengthConstraint: constraints.PathLengthConstraint);

                    var resultWithValue = TrustFactSet<X509SigningCertificateBasicConstraintsFact>.Available(fact);
                    context.MemoryCache?.Set(cacheKey, resultWithValue);
                    return new ValueTask<ITrustFactSet>(resultWithValue);
                }
            }

            var result = TrustFactSet<X509SigningCertificateBasicConstraintsFact>.Available();
            context.MemoryCache?.Set(cacheKey, result);
            return new ValueTask<ITrustFactSet>(result);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509SigningCertificateBasicConstraintsFact).FullName ?? nameof(X509SigningCertificateBasicConstraintsFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509SigningCertificateBasicConstraintsFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedBasicConstraints,
                    ex));
        }
    }

    private static ValueTask<ITrustFactSet> ProduceX5ChainIdentities(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(X509X5ChainCertificateIdentityFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<X509X5ChainCertificateIdentityFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(X509X5ChainCertificateIdentityFact).FullName ?? nameof(X509X5ChainCertificateIdentityFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        try
        {
            if (!context.Message!.TryGetCertificateChain(out X509Certificate2Collection? chain, CoseHeaderLocation.Any) || chain == null || chain.Count == 0)
            {
                LogX5ChainNotFound(logger);
                return new ValueTask<ITrustFactSet>(
                    TrustFactSet<X509X5ChainCertificateIdentityFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingX5ChainNotFound));
            }

            var facts = new List<X509X5ChainCertificateIdentityFact>(chain.Count);
            for (int i = 0; i < chain.Count; i++)
            {
                X509Certificate2 certificate = chain[i];
                facts.Add(new X509X5ChainCertificateIdentityFact(
                    index: i,
                    certificateThumbprint: certificate.GetCertHashString(),
                    subject: certificate.Subject,
                    issuer: certificate.Issuer));
            }

            var result = TrustFactSet<X509X5ChainCertificateIdentityFact>.Available(facts.ToArray());
            context.MemoryCache?.Set(cacheKey, result);
            return new ValueTask<ITrustFactSet>(result);
        }
        catch (Exception ex)
        {
            LogProducerFailed(logger, ex, typeof(X509X5ChainCertificateIdentityFact).FullName ?? nameof(X509X5ChainCertificateIdentityFact));
            return new ValueTask<ITrustFactSet>(
                TrustFactSet<X509X5ChainCertificateIdentityFact>.Missing(
                    TrustFactMissingCodes.ProducerFailed,
                    ClassStrings.ProducerFailedX5ChainIdentities,
                    ex));
        }
    }
}
