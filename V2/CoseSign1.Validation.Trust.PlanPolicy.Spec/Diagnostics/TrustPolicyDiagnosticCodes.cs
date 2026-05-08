// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Stable diagnostic codes emitted by trust-policy translation, binding, and compilation.
/// </summary>
/// <remarks>
/// <para>
/// Codes are append-only: never reuse a retired code. Ranges follow design decision D6.
/// </para>
/// <list type="table">
///   <listheader><term>Range</term><description>Category</description></listheader>
///   <item><term>TPX001–TPX099</term><description>Parse / syntax errors (frontend-defined).</description></item>
///   <item><term>TPX100–TPX199</term><description>Schema validation (frontend-defined).</description></item>
///   <item><term>TPX200–TPX299</term><description>Capability errors (unknown fact id, predicate-schema mismatch).</description></item>
///   <item><term>TPX300–TPX399</term><description>Translation errors (untranslatable construct, forbidden builtin).</description></item>
///   <item><term>TPX400–TPX499</term><description>Runtime guard errors (parameter binding, depth limits).</description></item>
///   <item><term>TPX900–TPX999</term><description>Reserved for tooling extensions.</description></item>
/// </list>
/// </remarks>
public static class TrustPolicyDiagnosticCodes
{
    /// <summary>The fact id referenced by a <see cref="Requirements.RequireFactSpec"/> is not present in the supplied <see cref="Registry.IFactRegistry"/>.</summary>
    public const string UnknownFactId = ClassStrings.CodeUnknownFactId;

    /// <summary>A predicate references a property that does not exist on the resolved fact CLR type.</summary>
    public const string UnknownFactProperty = ClassStrings.CodeUnknownFactProperty;

    /// <summary>A predicate uses an operator that cannot be lowered for the resolved fact CLR type and predicate value type.</summary>
    public const string UnsupportedPredicateOperator = ClassStrings.CodeUnsupportedPredicateOperator;

    /// <summary>A predicate path could not be resolved against the fact's JSON projection.</summary>
    public const string UnsupportedPredicatePath = ClassStrings.CodeUnsupportedPredicatePath;

    /// <summary>A <see cref="Requirements.RequireFactSpec"/> targets a fact whose CLR type does not match the requirement scope (e.g., a counter-signature fact in a primary-signing-key requirement).</summary>
    public const string FactScopeMismatch = ClassStrings.CodeFactScopeMismatch;

    /// <summary>A <see cref="Parameters.ParameterRef"/> survived into <see cref="Compilation.TrustPolicySpecCompiler.Compile"/> without being bound to a concrete value.</summary>
    public const string UnboundParameter = ClassStrings.CodeUnboundParameter;

    /// <summary>Diagnostic-code prefix shared by all trust-policy diagnostics.</summary>
    public const string Prefix = ClassStrings.CodePrefix;
}
