// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;

/// <summary>
/// Trivial <see cref="ITrustPack"/> that produces a fixed value for a single fact type when the
/// subject scope matches. Used by the compiler tests to verify spec-built and fluent-built plans
/// agree on evaluation outcome for a controlled fact world.
/// </summary>
internal sealed class FixedFactProducer<TFact> : ITrustPack
    where TFact : ITrustFact
{
    private readonly TFact[] Values;
    private readonly TrustSubjectKind ProducerScope;

    public FixedFactProducer(TrustSubjectKind scope, params TFact[] values)
    {
        ProducerScope = scope;
        Values = values;
    }

    public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TFact) };

    public CoseSign1.Validation.Interfaces.ISigningKeyResolver? SigningKeyResolver => null;

    public TrustPlanDefaults GetDefaults()
    {
        return new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.AllowAll() },
            vetoes: TrustRules.DenyAll("none"));
    }

    public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
    {
        if (context.Subject.Kind != ProducerScope)
        {
            return new ValueTask<ITrustFactSet>(TrustFactSet<TFact>.Available());
        }

        return new ValueTask<ITrustFactSet>(TrustFactSet<TFact>.Available(Values));
    }
}
