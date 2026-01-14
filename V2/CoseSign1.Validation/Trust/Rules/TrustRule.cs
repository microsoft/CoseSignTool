// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Rules;

using CoseSign1.Validation.Trust.Plan;

/// <summary>
/// A boolean rule evaluated by a <see cref="CompiledTrustPlan"/>.
/// </summary>
public abstract class TrustRule
{
    /// <summary>
    /// Evaluates the rule asynchronously.
    /// </summary>
    /// <param name="context">The evaluation context.</param>
    /// <returns>A trust decision.</returns>
    public abstract ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context);

    /// <summary>
    /// Evaluates the rule synchronously.
    /// </summary>
    /// <param name="context">The evaluation context.</param>
    /// <returns>A trust decision.</returns>
    public TrustDecision Evaluate(TrustRuleContext context)
    {
        return EvaluateAsync(context).AsTask().GetAwaiter().GetResult();
    }
}
