// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

using System;
using System.Globalization;
using System.Text.RegularExpressions;

/// <summary>
/// Stamps a concrete trust-fact CLR type with the stable, version-bearing identifier the
/// trust-policy translation contract uses to refer to that fact in serialized policies.
/// </summary>
/// <remarks>
/// <para>
/// Phase 3 (<c>tp-fact-registry</c>) co-locates the id with the fact (design decision D2) so
/// the id cannot drift away from the type that emits it. The Spec project's
/// <c>AttributeDrivenFactRegistry</c> reflects every loaded assembly whose name starts with
/// <c>CoseSign1.</c> for instances of this attribute and builds a bidirectional id ↔ type map.
/// </para>
/// <para>
/// Format constraint: ids MUST match the regex <c>^[a-z][a-z0-9-]*\/v[0-9]+$</c> — for example
/// <c>x509-chain-trusted/v1</c> or <c>mst-receipt-issuer-host/v2</c>. The version segment is
/// part of the id; breaking shape changes ship as a new id (e.g. <c>/v2</c>) rather than
/// mutating an existing one. Validation runs in the constructor so a mistyped id surfaces as
/// soon as the assembly is loaded — not days later when the registry first sees it.
/// </para>
/// <para>
/// Architectural note: the attribute physically lives in <c>CoseSign1.Validation</c> rather
/// than <c>CoseSign1.Validation.Trust.PlanPolicy.Spec</c> because the Spec project already
/// references the fact-host assemblies (Validation, Certificates, Transparent.MST), so a
/// reverse reference would form a cycle. Co-locating the attribute with <see cref="IMessageFact"/>,
/// <see cref="ISigningKeyFact"/>, and <see cref="ICounterSignatureFact"/> in this namespace
/// keeps every fact-related contract type in one place.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = false)]
public sealed class TrustFactIdAttribute : Attribute
{
    /// <summary>
    /// Regular-expression source the constructor enforces against incoming ids.
    /// </summary>
    public const string IdPattern = AssemblyStrings.TrustFactIdPattern;

    private static readonly Regex IdRegex = new(
        AssemblyStrings.TrustFactIdPattern,
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactIdAttribute"/> class.
    /// </summary>
    /// <param name="id">The stable fact identifier (e.g. <c>x509-chain-trusted/v1</c>).</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="id"/> is null, whitespace, or does not match <see cref="IdPattern"/>.
    /// </exception>
    public TrustFactIdAttribute(string id)
    {
        Cose.Abstractions.Guard.ThrowIfNullOrWhiteSpace(id);

        if (!IdRegex.IsMatch(id))
        {
            throw new ArgumentException(
                string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrTrustFactIdMalformedFormat, id, AssemblyStrings.TrustFactIdPattern),
                nameof(id));
        }

        Id = id;
    }

    /// <summary>Gets the stable fact identifier carried by this attribute.</summary>
    public string Id { get; }
}
