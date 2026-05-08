// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;

using System;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

/// <summary>
/// Spec-driven entry point for producing a <see cref="CompiledTrustPlan"/> that intentionally
/// bypasses <see cref="CompiledTrustPlan.CompileDefaults"/>'s pack-defaults composition.
/// </summary>
/// <remarks>
/// <para>
/// Implements design decision D8: when a host supplies an explicit
/// <see cref="TrustPolicySpec"/> (e.g. via the CLI's <c>--trust-policy</c> argument) the
/// document is the sole source of trust requirements for the invocation. Pack defaults are NOT
/// AND-merged in — that would conceal trust requirements behind a runtime composition the
/// operator cannot read off the document on disk.
/// </para>
/// <para>
/// Pack fact <strong>producers</strong> registered via DI remain available so the document's
/// <see cref="Requirements.RequireFactSpec"/> references resolve at evaluation time. Pack
/// <c>GetDefaults()</c> is what's bypassed — and that is exactly what
/// <see cref="TrustPlanPolicy.Compile"/> already does (it never invokes pack defaults).
/// </para>
/// <para>
/// Lives in the Spec project rather than as a static method on
/// <see cref="CompiledTrustPlan"/> because <c>CompiledTrustPlan</c> is in <c>CoseSign1.Validation</c>
/// and the Spec project depends on Validation — a method on the latter that takes a
/// <see cref="TrustPolicySpec"/> would induce a project cycle. A free static helper here keeps
/// the boundary clean and the surface additive.
/// </para>
/// </remarks>
public static class CompiledTrustPlanFromSpec
{
    /// <summary>
    /// Compiles <paramref name="spec"/> to a <see cref="CompiledTrustPlan"/> whose root rule is
    /// produced exclusively from the spec — pack defaults are NOT composed in.
    /// </summary>
    /// <param name="spec">The spec to compile. Must have all <see cref="Parameters.ParameterRef"/>
    /// nodes bound first via <see cref="TrustPolicySpecExtensions.Bind"/>.</param>
    /// <param name="registry">The fact-id → CLR-type registry resolving <c>RequireFactSpec.FactTypeId</c>.</param>
    /// <param name="services">The host service provider; supplies the registered
    /// <see cref="ITrustPack"/> instances whose fact producers are needed at evaluation time.</param>
    /// <returns>A <see cref="CompiledTrustPlan"/> rooted at the spec-derived rule.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    /// <exception cref="Diagnostics.TrustPolicySpecCompilationException">Thrown when the spec
    /// cannot be lowered to a <see cref="TrustPlanPolicy"/>.</exception>
    public static CompiledTrustPlan CompileFromSpec(
        TrustPolicySpec spec,
        IFactRegistry registry,
        IServiceProvider services)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);
        Cose.Abstractions.Guard.ThrowIfNull(registry);
        Cose.Abstractions.Guard.ThrowIfNull(services);

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, registry);

        // TrustPlanPolicy.Compile(IServiceProvider) explicitly does NOT compose pack defaults —
        // it only registers fact producers. That's exactly the D8-mandated semantics.
        return policy.Compile(services);
    }
}
