// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Lowers a <see cref="TrustPolicySpec"/> into the existing fluent
/// <see cref="TrustPlanPolicy"/> IR. Phase 1 of the translation contract.
/// </summary>
/// <remarks>
/// <para>
/// The compiler walks the spec tree:
/// </para>
/// <list type="bullet">
///   <item><description>requirement nodes (<see cref="MessageRequirementSpec"/>,
///   <see cref="PrimarySigningKeyRequirementSpec"/>, <see cref="AnyCounterSignatureRequirementSpec"/>)
///   route to <see cref="TrustPlanPolicy"/>'s static factories;</description></item>
///   <item><description>combinator nodes (<see cref="AndSpec"/>, <see cref="OrSpec"/>, <see cref="NotSpec"/>,
///   <see cref="ImpliesSpec"/>) route to <see cref="TrustPlanPolicy"/> instance combinators when
///   their operands are themselves spec policies, or to <see cref="TrustRules"/> factories when
///   they live inside a requirement scope;</description></item>
///   <item><description><see cref="RequireFactSpec"/> resolves the fact CLR type via the
///   supplied <see cref="IFactRegistry"/>, lowers the predicate via <see cref="PredicateLowerer"/>,
///   and emits a <see cref="TrustRules.AnyFact{TFact}"/> rule.</description></item>
/// </list>
/// <para>
/// The existing <see cref="TrustPlanPolicy"/> public fluent API is not modified. The compiler
/// reaches into the fluent builders' internal <c>AddRule</c> entry point so that
/// <see cref="RequireFactSpec"/> nodes nested inside arbitrary combinators can be lowered
/// without losing the scope context introduced by the wrapping requirement.
/// </para>
/// </remarks>
public static class TrustPolicySpecCompiler
{
    /// <summary>
    /// Compiles <paramref name="spec"/> into a runtime <see cref="TrustPlanPolicy"/>.
    /// </summary>
    /// <param name="spec">The spec to compile. Any <see cref="Parameters.ParameterRef"/> placeholders MUST
    /// be bound by <see cref="TrustPolicySpecExtensions.Bind"/> before calling Compile —
    /// unbound parameters are a compile-time error.</param>
    /// <param name="registry">The fact-id → CLR-type registry used to resolve
    /// <see cref="RequireFactSpec.FactTypeId"/>.</param>
    /// <returns>A runtime <see cref="TrustPlanPolicy"/> that is functionally equivalent to the
    /// fluent expression of the same logical policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="spec"/> or <paramref name="registry"/> is null.</exception>
    /// <exception cref="TrustPolicySpecCompilationException">Thrown when the spec cannot be lowered. The
    /// <see cref="TrustPolicySpecCompilationException.Code"/> property identifies the failure category.</exception>
    public static TrustPlanPolicy Compile(TrustPolicySpec spec, IFactRegistry registry)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);
        Cose.Abstractions.Guard.ThrowIfNull(registry);

        return CompilePolicy(spec, registry);
    }

    private static TrustPlanPolicy CompilePolicy(TrustPolicySpec spec, IFactRegistry registry)
    {
        return spec switch
        {
            MessageRequirementSpec mr => TrustPlanPolicy.Message(b =>
            {
                b.AddRule(LowerScoped(mr.Inner, registry, FactScope.Message));
                return b;
            }),
            PrimarySigningKeyRequirementSpec ps => TrustPlanPolicy.PrimarySigningKey(b =>
            {
                b.AddRule(LowerScoped(ps.Inner, registry, FactScope.SigningKey));
                return b;
            }),
            AnyCounterSignatureRequirementSpec acs => TrustPlanPolicy.AnyCounterSignature(b =>
            {
                b.OnEmpty(acs.OnEmpty);
                b.AddRule(LowerScoped(acs.Inner, registry, FactScope.CounterSignature));
                return b;
            }),
            AndSpec and => CombineAnd(and, registry),
            OrSpec or => CombineOr(or, registry),
            NotSpec not => CompilePolicy(not.Operand, registry).Not(),
            ImpliesSpec impl => TrustPlanPolicy.Implies(
                CompilePolicy(impl.Antecedent, registry),
                CompilePolicy(impl.Consequent, registry)),
            AllowAllSpec => TrustPlanPolicy.Message(b => b),
            DenyAllSpec deny => TrustPlanPolicy.Message(b =>
            {
                b.AddRule(TrustRules.DenyAll(deny.Reason));
                return b;
            }),
            RequireFactSpec => throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.FactScopeMismatch,
                ClassStrings.ErrRequireFactOutsideScope),
            _ => throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnsupportedPredicateOperator,
                string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrUnknownSpecNodeFormat, spec.GetType().FullName)),
        };
    }

    private static TrustPlanPolicy CombineAnd(AndSpec spec, IFactRegistry registry)
    {
        if (spec.Operands.Count == 0)
        {
            // Vacuously trusted — match TrustRules.And's "no reasons" → trusted semantics.
            return TrustPlanPolicy.Message(b => b);
        }

        TrustPlanPolicy current = CompilePolicy(spec.Operands[0], registry);
        for (int i = 1; i < spec.Operands.Count; i++)
        {
            current = current.And(CompilePolicy(spec.Operands[i], registry));
        }

        return current;
    }

    private static TrustPlanPolicy CombineOr(OrSpec spec, IFactRegistry registry)
    {
        if (spec.Operands.Count == 0)
        {
            // OrRule with empty operand list denies — wrap a DenyAll requirement so the policy
            // surface is consistent with the canonical IR semantics.
            return TrustPlanPolicy.Message(b =>
            {
                b.AddRule(TrustRules.DenyAll(ClassStrings.ReasonNoTrustSourcesSatisfied));
                return b;
            });
        }

        TrustPlanPolicy current = CompilePolicy(spec.Operands[0], registry);
        for (int i = 1; i < spec.Operands.Count; i++)
        {
            current = current.Or(CompilePolicy(spec.Operands[i], registry));
        }

        return current;
    }

    private static TrustRule LowerScoped(TrustPolicySpec spec, IFactRegistry registry, FactScope scope)
    {
        switch (spec)
        {
            case RequireFactSpec rf:
                return LowerRequireFact(rf, registry, scope);

            case AndSpec and:
                if (and.Operands.Count == 0)
                {
                    return TrustRules.AllowAll();
                }

                return TrustRules.And(and.Operands.Select(o => LowerScoped(o, registry, scope)).ToArray());

            case OrSpec or:
                if (or.Operands.Count == 0)
                {
                    return TrustRules.DenyAll(ClassStrings.ReasonNoTrustSourcesSatisfied);
                }

                return TrustRules.Or(or.Operands.Select(o => LowerScoped(o, registry, scope)).ToArray());

            case NotSpec not:
                return TrustRules.Not(LowerScoped(not.Operand, registry, scope), not.Reason);

            case ImpliesSpec impl:
                return TrustRules.Implies(
                    LowerScoped(impl.Antecedent, registry, scope),
                    LowerScoped(impl.Consequent, registry, scope));

            case AllowAllSpec:
                return TrustRules.AllowAll();

            case DenyAllSpec deny:
                return TrustRules.DenyAll(deny.Reason);

            case MessageRequirementSpec:
            case PrimarySigningKeyRequirementSpec:
            case AnyCounterSignatureRequirementSpec:
                throw new TrustPolicySpecCompilationException(
                    TrustPolicyDiagnosticCodes.FactScopeMismatch,
                    ClassStrings.ErrRequirementInScope);

            default:
                throw new TrustPolicySpecCompilationException(
                    TrustPolicyDiagnosticCodes.UnsupportedPredicateOperator,
                    string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrUnknownNodeInScopeFormat, spec.GetType().FullName));
        }
    }

    private static TrustRule LowerRequireFact(RequireFactSpec spec, IFactRegistry registry, FactScope scope)
    {
        if (!registry.TryGetFactType(spec.FactTypeId, out var factType))
        {
            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnknownFactId,
                string.Format(
                    CultureInfo.InvariantCulture,
                    ClassStrings.ErrUnknownFactIdFormat,
                    spec.FactTypeId,
                    string.Join(ClassStrings.JoinSeparator, registry.AllFactIds)));
        }

        AssertScopeMatches(factType, spec.FactTypeId, scope);

        // Validate property access at compile time — fail-fast when frontends reference a property
        // that does not exist on the fact's JSON projection.
        var referencedProperties = ExtractReferencedPropertyNames(spec.Predicate);
        if (referencedProperties.Count > 0)
        {
            PredicateLowerer.ValidatePropertyAccess(factType, referencedProperties, spec.FactTypeId);
        }

        Func<object, bool> objPredicate = PredicateLowerer.Compile(factType, spec.FactTypeId, spec.Predicate);

        // Reflectively call TrustRules.AnyFact<TFact>(...) with the typed predicate adapter.
        var adapterType = typeof(TypedPredicateAdapter<>).MakeGenericType(factType);
        object adapter = Activator.CreateInstance(adapterType, objPredicate)!;
        var funcType = typeof(Func<,>).MakeGenericType(factType, typeof(bool));
        var evaluateMethod = adapterType.GetMethod(nameof(TypedPredicateAdapter<object>.Evaluate))!;
        Delegate typedPredicate = Delegate.CreateDelegate(funcType, adapter, evaluateMethod);

        var anyFactMethod = typeof(TrustRules)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Single(m => m.Name == nameof(TrustRules.AnyFact) && m.IsGenericMethodDefinition)
            .MakeGenericMethod(factType);

        return (TrustRule)anyFactMethod.Invoke(
            null,
            new object?[]
            {
                typedPredicate,
                spec.FailureMessage,
                spec.FailureMessage,
                OnEmptyBehavior.Deny,
                spec.FailureMessage,
            })!;
    }

    private static IReadOnlyList<string> ExtractReferencedPropertyNames(FactPredicateSpec predicate)
    {
        // Path-operator forms describe JSON-traversal expressions; their leading property accessor
        // is a navigation step, not an assertion of property presence. Compile-time validation is
        // limited to property-assertion forms where every key is an explicit property name on the
        // fact's JSON projection.
        return predicate switch
        {
            PropertyAssertionPredicateSpec pa => pa.Assertions.Keys.ToArray(),
            _ => Array.Empty<string>(),
        };
    }

    private static void AssertScopeMatches(Type factType, string factTypeId, FactScope scope)
    {
        bool matches = scope switch
        {
            FactScope.Message => typeof(IMessageFact).IsAssignableFrom(factType),
            FactScope.SigningKey => typeof(ISigningKeyFact).IsAssignableFrom(factType),
            FactScope.CounterSignature => typeof(ICounterSignatureFact).IsAssignableFrom(factType)
                || typeof(ISigningKeyFact).IsAssignableFrom(factType),
            _ => false,
        };

        if (!matches)
        {
            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.FactScopeMismatch,
                string.Format(
                    CultureInfo.InvariantCulture,
                    ClassStrings.ErrFactScopeMismatchFormat,
                    factTypeId,
                    factType.FullName,
                    scope));
        }
    }

    private enum FactScope
    {
        Message,
        SigningKey,
        CounterSignature,
    }

    /// <summary>
    /// Generic adapter that converts a runtime <see cref="System.Func{T, TResult}"/>-shaped
    /// predicate over <see cref="object"/> into the strongly-typed predicate signature expected
    /// by <see cref="TrustRules.AnyFact{TFact}"/>. Internal — used by the compiler only.
    /// </summary>
    /// <typeparam name="TFact">The fact CLR type.</typeparam>
    internal sealed class TypedPredicateAdapter<TFact>
    {
        private readonly Func<object, bool> Inner;

        public TypedPredicateAdapter(Func<object, bool> inner)
        {
            Cose.Abstractions.Guard.ThrowIfNull(inner);
            Inner = inner;
        }

        public bool Evaluate(TFact fact) => Inner(fact!);
    }
}
