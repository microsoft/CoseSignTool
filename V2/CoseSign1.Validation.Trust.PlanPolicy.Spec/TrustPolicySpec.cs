// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec;

using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;

/// <summary>
/// Sealed discriminated union: the canonical translation target every trust-policy frontend
/// must produce. Compiled by <see cref="Compilation.TrustPolicySpecCompiler"/> into the existing
/// fluent <see cref="CoseSign1.Validation.Trust.TrustPlanPolicy"/>.
/// </summary>
/// <remarks>
/// <para>
/// Decision D3: <c>System.Text.Json</c> polymorphism with a <c>type</c> discriminator. The closed
/// type set is the contract — extensions cannot smuggle new spec node types past the
/// conformance suite. All concrete types are <c>sealed record</c> so structural equality and
/// canonical hashing are stable.
/// </para>
/// <para>
/// Every node carries an optional <see cref="Location"/> for diagnostics. Frontends populate
/// it; the binder pass (see <see cref="Parameters.ParameterRef.Bind"/>) preserves it through
/// substitution.
/// </para>
/// </remarks>
[JsonPolymorphic(TypeDiscriminatorPropertyName = ClassStrings.DiscriminatorPropertyName)]
[JsonDerivedType(typeof(MessageRequirementSpec), ClassStrings.DiscriminatorMessage)]
[JsonDerivedType(typeof(PrimarySigningKeyRequirementSpec), ClassStrings.DiscriminatorPrimarySigningKey)]
[JsonDerivedType(typeof(AnyCounterSignatureRequirementSpec), ClassStrings.DiscriminatorAnyCounterSignature)]
[JsonDerivedType(typeof(RequireFactSpec), ClassStrings.DiscriminatorRequireFact)]
[JsonDerivedType(typeof(AndSpec), ClassStrings.DiscriminatorAnd)]
[JsonDerivedType(typeof(OrSpec), ClassStrings.DiscriminatorOr)]
[JsonDerivedType(typeof(NotSpec), ClassStrings.DiscriminatorNot)]
[JsonDerivedType(typeof(ImpliesSpec), ClassStrings.DiscriminatorImplies)]
[JsonDerivedType(typeof(AllowAllSpec), ClassStrings.DiscriminatorAllowAll)]
[JsonDerivedType(typeof(DenyAllSpec), ClassStrings.DiscriminatorDenyAll)]
public abstract record TrustPolicySpec
{
    /// <summary>Initializes a new instance of the <see cref="TrustPolicySpec"/> class.</summary>
    private protected TrustPolicySpec()
    {
    }

    /// <summary>
    /// Optional source location attached by the frontend. Phase 1 leaves it null.
    /// </summary>
    [JsonPropertyName(ClassStrings.PropertyLocation)]
    [JsonPropertyOrder(1000)]
    public SourceLocation? Location { get; init; }
}
