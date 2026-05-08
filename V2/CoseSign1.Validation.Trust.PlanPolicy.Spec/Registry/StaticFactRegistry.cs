// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Hand-rolled in-memory <see cref="IFactRegistry"/> covering every concrete fact type currently
/// shipped by the V2 trust packs.
/// </summary>
/// <remarks>
/// <para>
/// Temporary; superseded by the attribute-driven registry in Phase 3 (<c>tp-fact-registry</c>).
/// New facts added between phases MUST be added here so the spec compiler can resolve them.
/// </para>
/// <para>
/// All ids carry an explicit <c>/v1</c> suffix per design decision D2 — the version is part of
/// the id so breaking shape changes ship as new ids rather than mutations of existing ones.
/// </para>
/// </remarks>
public sealed class StaticFactRegistry : IFactRegistry
{
    private readonly IReadOnlyDictionary<string, Type> IdToType;
    private readonly IReadOnlyDictionary<Type, string> TypeToId;
    private readonly IReadOnlySet<string> Ids;

    /// <summary>
    /// Initializes a new instance of the <see cref="StaticFactRegistry"/> class with the default
    /// V2 mappings.
    /// </summary>
    public StaticFactRegistry()
        : this(BuildDefaultMappings())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="StaticFactRegistry"/> class with explicit mappings.
    /// Useful for tests that need to register synthetic fact types.
    /// </summary>
    /// <param name="mappings">Stable fact id → CLR type map. Both directions are validated.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="mappings"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when an id is empty / whitespace, or a CLR type is referenced under two different ids.</exception>
    public StaticFactRegistry(IEnumerable<KeyValuePair<string, Type>> mappings)
    {
        Cose.Abstractions.Guard.ThrowIfNull(mappings);

        // Materialise the mapping once so the validation loop is single-pass and so callers
        // that pass deferred enumerables don't trigger multiple enumerations.
        var materialised = mappings as IReadOnlyList<KeyValuePair<string, Type>> ?? mappings.ToList();

        var idToType = new Dictionary<string, Type>(StringComparer.Ordinal);
        var typeToId = new Dictionary<Type, string>();

        foreach (var pair in materialised)
        {
            if (string.IsNullOrWhiteSpace(pair.Key))
            {
                throw new ArgumentException(ClassStrings.ErrFactIdNullOrWhitespace, nameof(mappings));
            }

            if (pair.Value is null)
            {
                throw new ArgumentException(ClassStrings.ErrFactClrTypeNull, nameof(mappings));
            }

            if (idToType.ContainsKey(pair.Key))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrDuplicateFactIdFormat, pair.Key), nameof(mappings));
            }

            if (typeToId.TryGetValue(pair.Value, out var existingId))
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrDuplicateFactClrTypeFormat, pair.Value.FullName, existingId),
                    nameof(mappings));
            }

            idToType[pair.Key] = pair.Value;
            typeToId[pair.Value] = pair.Key;
        }

        IdToType = idToType;
        TypeToId = typeToId;
        Ids = new SortedSet<string>(idToType.Keys, StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public IReadOnlySet<string> AllFactIds => Ids;

    /// <inheritdoc />
    public bool TryGetFactType(string factId, [NotNullWhen(true)] out Type? clrType)
    {
        Cose.Abstractions.Guard.ThrowIfNull(factId);

        return IdToType.TryGetValue(factId, out clrType);
    }

    /// <inheritdoc />
    public bool TryGetFactId(Type clrType, [NotNullWhen(true)] out string? factId)
    {
        Cose.Abstractions.Guard.ThrowIfNull(clrType);

        return TypeToId.TryGetValue(clrType, out factId);
    }

    /// <summary>
    /// Returns the default (id, CLR-type) mapping baked into Phase 1. Exposed for diagnostics
    /// and test composition; production callers should use <see cref="StaticFactRegistry()"/>.
    /// </summary>
    /// <returns>The canonical default mapping list.</returns>
    public static IReadOnlyList<KeyValuePair<string, Type>> BuildDefaultMappings()
    {
        // Order is intentional: facts are grouped by pack so the registry's contents read as a
        // catalog rather than a hash-table dump.
        return new[]
        {
            // Core message-scoped facts (CoseSign1.Validation).
            new KeyValuePair<string, Type>(ClassStrings.FactContentType, typeof(ContentTypeFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactCounterSignatureSubject, typeof(CounterSignatureSubjectFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactDetachedPayloadPresent, typeof(DetachedPayloadPresentFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactUnknownCounterSignatureBytes, typeof(UnknownCounterSignatureBytesFact)),

            // Certificate trust pack (CoseSign1.Certificates).
            new KeyValuePair<string, Type>(ClassStrings.FactCertificateSigningKeyTrust, typeof(CertificateSigningKeyTrustFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509ChainElementIdentity, typeof(X509ChainElementIdentityFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509ChainTrusted, typeof(X509ChainTrustedFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509CertBasicConstraints, typeof(X509SigningCertificateBasicConstraintsFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509CertEku, typeof(X509SigningCertificateEkuFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509CertIdentityAllowed, typeof(X509SigningCertificateIdentityAllowedFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509CertIdentity, typeof(X509SigningCertificateIdentityFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509CertKeyUsage, typeof(X509SigningCertificateKeyUsageFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactX509X5ChainCertIdentity, typeof(X509X5ChainCertificateIdentityFact)),

            // MST transparent-statement trust pack (CoseSign1.Transparent.MST).
            new KeyValuePair<string, Type>(ClassStrings.FactMstReceiptIssuerHost, typeof(MstReceiptIssuerHostFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactMstReceiptPresent, typeof(MstReceiptPresentFact)),
            new KeyValuePair<string, Type>(ClassStrings.FactMstReceiptTrusted, typeof(MstReceiptTrustedFact)),
        }.OrderBy(kvp => kvp.Key, StringComparer.Ordinal).ToArray();
    }
}
